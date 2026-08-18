// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli/files.h"

#include "core/text_chunks.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>

namespace scitt_sd::cli
{
  namespace fs = std::filesystem;

  namespace
  {
    std::string describe_errno(int error)
    {
      return std::error_code(error, std::generic_category()).message();
    }

    std::string quoted(const fs::path& path)
    {
      return "'" + path.string() + "'";
    }

    // Owner read/write only.
    constexpr mode_t PRIVATE_MODE = 0600;
    // Owner read/write, everyone else read. fchmod does not consult the
    // umask, so this is exactly what a shareable file ends up with, whichever
    // umask the caller happens to be running under.
    constexpr mode_t SHAREABLE_MODE = 0644;

    // Closes a descriptor exactly once, however the scope is left.
    class OwnedFd
    {
    public:
      explicit OwnedFd(int fd) : fd_(fd) {}
      OwnedFd(const OwnedFd&) = delete;
      OwnedFd& operator=(const OwnedFd&) = delete;
      OwnedFd(OwnedFd&&) = delete;
      OwnedFd& operator=(OwnedFd&&) = delete;

      ~OwnedFd()
      {
        reset();
      }

      [[nodiscard]] int get() const
      {
        return fd_;
      }

      void reset()
      {
        (void)close();
      }

      // Closes the descriptor, reporting whether close() itself succeeded.
      // Closing an already closed descriptor is a no-op and succeeds.
      bool close()
      {
        if (fd_ < 0)
        {
          return true;
        }
        const auto fd = fd_;
        // Cleared first: whatever close() returns, the descriptor must not be
        // closed a second time.
        fd_ = -1;
        return ::close(fd) == 0;
      }

    private:
      int fd_;
    };

    // Removes a temporary file unless it was renamed into place.
    class ScopedTemp
    {
    public:
      explicit ScopedTemp(fs::path path) : path_(std::move(path)) {}
      ScopedTemp(const ScopedTemp&) = delete;
      ScopedTemp& operator=(const ScopedTemp&) = delete;
      ScopedTemp(ScopedTemp&&) = delete;
      ScopedTemp& operator=(ScopedTemp&&) = delete;

      ~ScopedTemp()
      {
        if (!path_.empty())
        {
          std::error_code ignored;
          (void)fs::remove(path_, ignored);
        }
      }

      void release()
      {
        path_.clear();
      }

    private:
      fs::path path_;
    };

    void write_all(
      int fd, std::span<const uint8_t> contents, const fs::path& to)
    {
      size_t written = 0;
      while (written < contents.size())
      {
        const auto chunk = ::write(
          fd,
          contents.data() + written,
          static_cast<size_t>(contents.size() - written));
        if (chunk < 0)
        {
          const auto error = errno;
          if (error == EINTR)
          {
            continue;
          }
          throw UsageError(
            "could not write " + quoted(to) + ": " + describe_errno(error));
        }
        written += static_cast<size_t>(chunk);
      }
    }
  }

  std::vector<uint8_t> read_file(
    const fs::path& path, size_t max_bytes, std::string_view description)
  {
    std::error_code error;
    const auto status = fs::status(path, error);
    if (error)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) +
        " cannot be read: " + error.message());
    }
    if (status.type() == fs::file_type::not_found)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) + " does not exist");
    }
    if (!fs::is_regular_file(status))
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) +
        " is not a regular file");
    }

    // The size is checked BEFORE the read, so an oversized file costs nothing.
    const auto size = fs::file_size(path, error);
    if (error)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) +
        " cannot be measured: " + error.message());
    }
    if (size > max_bytes)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) + " is larger than the " +
        std::to_string(max_bytes) + " byte limit");
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) + " could not be opened");
    }
    std::vector<uint8_t> contents(static_cast<size_t>(size));
    if (size > 0)
    {
      stream.read(
        reinterpret_cast<char*>(contents.data()),
        static_cast<std::streamsize>(size));
      if (stream.gcount() != static_cast<std::streamsize>(size))
      {
        throw UsageError(
          std::string(description) + " " + quoted(path) +
          " could not be read in full");
      }
    }
    if (contents.empty())
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) + " is empty");
    }
    return contents;
  }

  std::string read_text_file(
    const fs::path& path, size_t max_bytes, std::string_view description)
  {
    const auto bytes = read_file(path, max_bytes, description);
    std::string text(bytes.begin(), bytes.end());
    if (text.find('\0') != std::string::npos)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) +
        " contains a NUL character");
    }
    try
    {
      text::validate_utf8(text);
    }
    catch (const std::exception&)
    {
      throw UsageError(
        std::string(description) + " " + quoted(path) +
        " is not well-formed UTF-8");
    }
    return text;
  }

  void write_file(
    const fs::path& path, std::span<const uint8_t> contents, Access access)
  {
    const auto directory =
      path.has_parent_path() ? path.parent_path() : fs::path(".");
    std::error_code error;
    if (!fs::is_directory(directory, error))
    {
      throw UsageError(
        "cannot write " + quoted(path) + ": the directory " +
        quoted(directory) + " does not exist");
    }

    // mkstemp creates the file 0600 and fails rather than following an
    // existing name, so nothing can be tricked into writing through a symlink
    // and no other user ever sees the content of a private file.
    auto pattern =
      (directory / (path.filename().string() + ".tmpXXXXXX")).string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back('\0');
    OwnedFd fd(::mkstemp(buffer.data()));
    if (fd.get() < 0)
    {
      const auto saved_errno = errno;
      throw UsageError(
        "cannot write " + quoted(path) + ": " + describe_errno(saved_errno));
    }
    const fs::path temporary(buffer.data());
    ScopedTemp cleanup(temporary);

    write_all(fd.get(), contents, path);

    // 0600 is right for a private key and wrong for everything else, which an
    // operator is expected to be able to read.
    const mode_t mode =
      access == Access::Shareable ? SHAREABLE_MODE : PRIVATE_MODE;
    if (::fchmod(fd.get(), mode) != 0)
    {
      const auto saved_errno = errno;
      throw UsageError(
        "cannot set the permissions of " + quoted(path) + ": " +
        describe_errno(saved_errno));
    }

    // The content must reach the disk before the rename, or a crash can leave
    // the new name pointing at an empty file.
    if (::fsync(fd.get()) != 0)
    {
      const auto saved_errno = errno;
      throw UsageError(
        "cannot flush " + quoted(path) + ": " + describe_errno(saved_errno));
    }
    // close() can fail (a deferred write-back error, for instance), and a
    // failure there means the content never reached the disk, so the rename
    // must not happen.
    if (!fd.close())
    {
      const auto saved_errno = errno;
      throw UsageError(
        "cannot close " + quoted(path) + ": " + describe_errno(saved_errno));
    }

    if (::rename(temporary.c_str(), path.c_str()) != 0)
    {
      const auto saved_errno = errno;
      throw UsageError(
        "cannot replace " + quoted(path) + ": " + describe_errno(saved_errno));
    }
    cleanup.release();

    // Flushing the directory makes the rename itself durable.
    OwnedFd dir(::open(directory.c_str(), O_RDONLY | O_DIRECTORY));
    if (dir.get() >= 0)
    {
      (void)::fsync(dir.get());
    }
  }

  void write_text_file(
    const fs::path& path, std::string_view contents, Access access)
  {
    write_file(
      path,
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(contents.data()), contents.size()),
      access);
  }
}
