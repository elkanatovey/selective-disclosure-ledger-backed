// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// INTERNAL header: not part of the public core API. It exposes the injectable
// randomness source used by report issuance so tests can produce deterministic
// salts. Production callers include core/report.h, which always draws from the
// CCF entropy source.

#include "core/report.h"
#include "core/sd_cwt_internal.h"

namespace scitt_sd::report::detail
{
  // issue() with an explicit randomness source. See report.h for parameter
  // semantics.
  IssuedReport issue(
    const ReportInput& input,
    const IssuerIdentity& issuer,
    const ccf::crypto::ECKeyPair& key,
    sdcwt::HashAlg sd_alg,
    const sdcwt::RandomSource& rng);

  // prepare() with an explicit randomness source.
  PreparedReport prepare(
    const ReportInput& input,
    const IssuerIdentity& issuer,
    int64_t cose_alg,
    sdcwt::HashAlg sd_alg,
    const sdcwt::RandomSource& rng);
}
