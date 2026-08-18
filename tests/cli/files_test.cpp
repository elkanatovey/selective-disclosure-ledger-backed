// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The file layer is the only place the tool touches the filesystem, so its
// refusals (missing, oversized, not a regular file, not text) and its
// guarantees (atomic replacement, owner-only private files) are pinned here.

#include "cli/files.h"

#include "tests/cli/cli_test_support.h"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

using namespace scitt_sd::cli;
using scitt_sd::cli::testing::read_raw;
using scitt_sd::cli::testing::ScratchDir;
using scitt_sd::cli::testing::write_raw;

namespace
{
  std::filesystem::perms permissions_of(const std::filesystem::path& path)
  {
    return std::filesystem::status(path).permissions();
  }

  // Every entry in a directory, so a test can assert that no temporary file
  // was left behind next to the file it wrote.
  std::vector<std::string> entries_of(const std::filesystem::path& directory)
  {
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(directory))
    {
      names.push_back(entry.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    return names;
  }
}

TEST(FilesRead, ReadsExactBytes)
{
  const ScratchDir dir("files_exact");
  const auto path = dir / "payload.bin";
  const std::string contents("\x01\x02\x00\x03", 4);
  write_raw(path, contents);

  const auto bytes = read_file(path, 1024, "the payload");
  ASSERT_EQ(bytes.size(), 4U);
  EXPECT_EQ(bytes[0], 0x01);
  EXPECT_EQ(bytes[2], 0x00);
}

TEST(FilesRead, RefusesAMissingFile)
{
  const ScratchDir dir("files_missing");
  EXPECT_THROW(
    (void)read_file(dir / "absent.bin", 1024, "the payload"), UsageError);
}

TEST(FilesRead, RefusesADirectory)
{
  const ScratchDir dir("files_directory");
  std::filesystem::create_directories(dir / "sub");
  EXPECT_THROW((void)read_file(dir / "sub", 1024, "the payload"), UsageError);
}

TEST(FilesRead, RefusesAnEmptyFile)
{
  const ScratchDir dir("files_empty");
  const auto path = dir / "empty.bin";
  write_raw(path, "");
  EXPECT_THROW((void)read_file(path, 1024, "the payload"), UsageError);
}

TEST(FilesRead, RefusesAFileOverTheLimit)
{
  const ScratchDir dir("files_oversized");
  const auto path = dir / "big.bin";
  write_raw(path, std::string(64, 'a'));

  EXPECT_NO_THROW((void)read_file(path, 64, "the payload"));
  try
  {
    (void)read_file(path, 63, "the payload");
    FAIL() << "an oversized file must be refused";
  }
  catch (const UsageError& error)
  {
    EXPECT_NE(
      std::string(error.what()).find("63 byte limit"), std::string::npos);
  }
}

TEST(FilesRead, NamesTheFileAndItsDescription)
{
  const ScratchDir dir("files_named");
  const auto path = dir / "absent.pem";
  try
  {
    (void)read_file(path, 1024, "the root certificate");
    FAIL() << "a missing file must be refused";
  }
  catch (const UsageError& error)
  {
    const std::string message(error.what());
    EXPECT_NE(message.find("the root certificate"), std::string::npos);
    EXPECT_NE(message.find(path.string()), std::string::npos);
  }
}

TEST(FilesReadText, RefusesEmbeddedNul)
{
  const ScratchDir dir("files_nul");
  const auto path = dir / "text.txt";
  write_raw(path, std::string("ab\0cd", 5));
  EXPECT_THROW((void)read_text_file(path, 1024, "the text"), UsageError);
}

TEST(FilesReadText, RefusesMalformedUtf8)
{
  const ScratchDir dir("files_utf8");
  const auto path = dir / "text.txt";
  write_raw(path, std::string("\xC3\x28", 2));
  EXPECT_THROW((void)read_text_file(path, 1024, "the text"), UsageError);
}

TEST(FilesReadText, AcceptsMultiByteUtf8)
{
  const ScratchDir dir("files_utf8_ok");
  const auto path = dir / "text.txt";
  // U+00E9 and U+20AC, spelled as bytes so this file stays ASCII.
  const std::string contents("caf\xC3\xA9 \xE2\x82\xAC");
  write_raw(path, contents);
  EXPECT_EQ(read_text_file(path, 1024, "the text"), contents);
}

TEST(FilesWrite, WritesAShareableFileAndLeavesNoTemporary)
{
  const ScratchDir dir("files_write_shared");
  const auto path = dir / "public.pem";
  write_text_file(path, "hello");

  EXPECT_EQ(read_raw(path), "hello");
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"public.pem"});
}

TEST(FilesWrite, PrivateFilesAreOwnerOnly)
{
  const ScratchDir dir("files_write_private");
  const auto path = dir / "root.key";
  write_text_file(path, "secret", Access::Private);

  const auto mode = permissions_of(path);
  EXPECT_EQ(
    mode & std::filesystem::perms::owner_read,
    std::filesystem::perms::owner_read);
  EXPECT_EQ(
    mode & std::filesystem::perms::owner_write,
    std::filesystem::perms::owner_write);
  EXPECT_EQ(
    mode & std::filesystem::perms::group_all, std::filesystem::perms::none);
  EXPECT_EQ(
    mode & std::filesystem::perms::others_all, std::filesystem::perms::none);
}

TEST(FilesWrite, ReplacesTheWholeFileAtOnce)
{
  const ScratchDir dir("files_write_replace");
  const auto path = dir / "artifact.bin";
  write_text_file(path, "the original content");
  write_text_file(path, "new");

  EXPECT_EQ(read_raw(path), "new");
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"artifact.bin"});
}

TEST(FilesWrite, NarrowsAnExistingPrivateFileWhenRewrittenPrivate)
{
  const ScratchDir dir("files_write_stays_private");
  const auto path = dir / "root.key";
  write_text_file(path, "first", Access::Private);
  write_text_file(path, "second", Access::Private);

  EXPECT_EQ(read_raw(path), "second");
  EXPECT_EQ(
    permissions_of(path) & std::filesystem::perms::others_all,
    std::filesystem::perms::none);
}

TEST(FilesWrite, ShareableFilesAreReadableByEveryoneWhateverTheUmask)
{
  const ScratchDir dir("files_write_umask");
  const auto path = dir / "public.pem";

  // fchmod ignores the umask, so a restrictive one must not stop an operator
  // (or the control plane running as another user) from reading the file.
  const auto previous = ::umask(0077);
  write_text_file(path, "hello");
  (void)::umask(previous);

  const auto mode = permissions_of(path);
  EXPECT_EQ(
    mode & std::filesystem::perms::group_read,
    std::filesystem::perms::group_read);
  EXPECT_EQ(
    mode & std::filesystem::perms::others_read,
    std::filesystem::perms::others_read);
  EXPECT_EQ(
    mode & std::filesystem::perms::owner_write,
    std::filesystem::perms::owner_write);
  EXPECT_EQ(
    mode &
      (std::filesystem::perms::group_write |
       std::filesystem::perms::others_write |
       std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec |
       std::filesystem::perms::others_exec),
    std::filesystem::perms::none);
}

TEST(FilesWrite, WidensAnExistingPrivateFileWhenRewrittenShareable)
{
  const ScratchDir dir("files_write_widen");
  const auto path = dir / "artifact.bin";
  write_text_file(path, "first", Access::Private);
  write_text_file(path, "second");

  EXPECT_EQ(read_raw(path), "second");
  EXPECT_EQ(
    permissions_of(path) & std::filesystem::perms::others_read,
    std::filesystem::perms::others_read);
}

TEST(FilesWrite, WritesAnEmptyPayload)
{
  const ScratchDir dir("files_write_empty");
  const auto path = dir / "empty.bin";
  write_file(path, std::span<const uint8_t>());

  EXPECT_TRUE(std::filesystem::exists(path));
  EXPECT_EQ(std::filesystem::file_size(path), 0U);
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"empty.bin"});
}

TEST(FilesWrite, RefusesToReplaceADirectory)
{
  const ScratchDir dir("files_write_over_dir");
  std::filesystem::create_directory(dir / "occupied");
  EXPECT_THROW(write_text_file(dir / "occupied", "x"), UsageError);
  // The refusal must not have left a temporary behind.
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"occupied"});
}

TEST(FilesWrite, RefusesAMissingDirectory)
{
  const ScratchDir dir("files_write_nodir");
  EXPECT_THROW(
    write_text_file(dir / "absent" / "artifact.bin", "x"), UsageError);
}

TEST(FilesWrite, WritesIntoTheCurrentDirectoryWhenNoParentIsGiven)
{
  const ScratchDir dir("files_write_relative");
  const auto path = dir / "relative.bin";
  // A bare filename has no parent path: the write must land in ".", not fail.
  const auto previous = std::filesystem::current_path();
  std::filesystem::current_path(dir.path());
  write_text_file("relative.bin", "here");
  std::filesystem::current_path(previous);

  EXPECT_EQ(read_raw(path), "here");
}
