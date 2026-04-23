/*
 * Copyright (c) Mary Guillemard <mary@mary.zone>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include <stratosphere.hpp>
#include "networkmitm_ssl_types.hpp"

namespace ams::ssl::sf::impl {
#ifndef NETWORK_MITM_ENABLE_VERBOSE_LOGGING
#define NETWORK_MITM_ENABLE_VERBOSE_LOGGING 0
#endif

#if NETWORK_MITM_ENABLE_VERBOSE_LOGGING
#define NETWORK_MITM_VLOG(...) AMS_LOG(__VA_ARGS__)
#else
#define NETWORK_MITM_VLOG(...) ((void)0)
#endif

    extern bool g_should_mitm_all;
    extern bool g_should_mitm_system;
    extern bool g_should_disable_ssl_verification;

    constexpr u64 AmProgramId = 0x0100000000000023;

    inline const char *BoolString(bool value) {
        return value ? "true" : "false";
    }

    inline bool IsAmProgramId(ncm::ProgramId program_id) {
        return static_cast<u64>(program_id) == AmProgramId;
    }

    inline void LogResult(const char *label, Result result) {
        AMS_LOG("%s rc=0x%08x module=%u desc=%u\n", label, result.GetValue(),
                result.GetModule(), result.GetDescription());
    }

    bool ConvertPemToDer(Span<const uint8_t> pem_cert, Span<uint8_t> &der_cert, size_t &der_cert_size);

    enum class TrustedCertStatus : u32 {
        Removed,
        EnabledTrusted,
        EnabledNotTrusted,
        Revoked,
    };

    struct BuiltInCertificateInfo {
        ams::ssl::sf::CaCertificateId id;
        TrustedCertStatus status;
        uint64_t certificate_data_size;
        uint64_t certificate_data_offset;
    };

    Result PatchCertificates(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &certificates);
    Result PatchCertificateBufSize(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> buffer_size);
}
