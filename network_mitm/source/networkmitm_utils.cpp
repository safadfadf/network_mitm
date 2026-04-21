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

#include "networkmitm_utils.hpp"
#include <mbedtls/base64.h>

namespace ams::ssl::sf::impl {
extern Span<uint8_t> g_ca_certificate_public_key_der;

bool ConvertPemToDer(Span<const uint8_t> pem_cert, Span<uint8_t> &der_cert,
                     size_t &der_cert_size) {
    const char *s1;
    const char *s2;
    const char *end = (const char *)(pem_cert.data() + pem_cert.size_bytes());
    size_t len = 0;

    AMS_LOG("ConvertPemToDer begin pem_size=%zu der_capacity=%zu\n",
            pem_cert.size_bytes(), der_cert.size_bytes());

    s1 = strstr((const char *)pem_cert.data(), "-----BEGIN");

    if (s1 == nullptr) {
        AMS_LOG("ConvertPemToDer failed: BEGIN marker not found\n");
        return false;
    }

    s2 = strstr((const char *)pem_cert.data(), "-----END");

    if (s2 == nullptr) {
        AMS_LOG("ConvertPemToDer failed: END marker not found\n");
        return false;
    }

    s1 += 10;

    while (s1 < end && *s1 != '-') {
        s1++;
    }

    while (s1 < end && *s1 == '-') {
        s1++;
    }

    if (*s1 == '\r') {
        s1++;
    }

    if (*s1 == '\n') {
        s1++;
    }

    if (s2 <= s1 || s2 > end) {
        AMS_LOG("ConvertPemToDer failed: invalid PEM body range\n");
        return false;
    }

    if (mbedtls_base64_decode(nullptr, 0, &len, (const unsigned char *)s1,
                              s2 - s1) ==
        MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        AMS_LOG("ConvertPemToDer failed: invalid base64 body\n");
        return false;
    }

    if (len > der_cert.size_bytes()) {
        AMS_LOG("ConvertPemToDer failed: DER too large der_size=%zu "
                "capacity=%zu\n",
                len, der_cert.size_bytes());
        return false;
    }

    if (mbedtls_base64_decode(der_cert.data(), len, &len,
                              (const unsigned char *)s1, s2 - s1) != 0) {
        AMS_LOG("ConvertPemToDer failed: base64 decode error\n");
        return false;
    }

    der_cert_size = len;
    AMS_LOG("ConvertPemToDer success der_size=%zu\n", der_cert_size);

    return true;
}

Result
PatchCertificates(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
                  ams::sf::Out<u32> certificates_count,
                  const ams::sf::OutBuffer &certificates) {
    if (g_ca_certificate_public_key_der.empty()) {
        AMS_LOG("PatchCertificates skipped: no custom CA DER loaded "
                "ids=%zu out_size=%zu\n",
                ids.GetSize(), certificates.GetSize());
        R_SUCCEED();
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        AMS_LOG("PatchCertificates inspect id[%zu]=%u\n", i,
                static_cast<u32>(ids[i]));
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All ||
            ids[i] == ams::ssl::sf::CaCertificateId::NewAll) {
            should_inject = true;
            AMS_LOG("PatchCertificates injection requested by id[%zu]=%u\n", i,
                    static_cast<u32>(ids[i]));
            break;
        }
    }

    if (should_inject) {
        const auto certificates_count_value = certificates_count.GetValue();
        AMS_LOG("PatchCertificates begin count=%u out_size=%zu der_size=%zu\n",
                certificates_count_value, certificates.GetSize(),
                g_ca_certificate_public_key_der.size_bytes());

        BuiltInCertificateInfo *infos =
            reinterpret_cast<BuiltInCertificateInfo *>(
                certificates.GetPointer());

        u64 target_offset =
            infos[certificates_count_value - 1].certificate_data_offset +
            infos[certificates_count_value - 1].certificate_data_size;
        AMS_LOG("PatchCertificates target_offset=%lx last_id=%u last_offset=%lx "
                "last_size=%lx\n",
                target_offset,
                static_cast<u32>(infos[certificates_count_value - 1].id),
                infos[certificates_count_value - 1].certificate_data_offset,
                infos[certificates_count_value - 1].certificate_data_size);

        memcpy(certificates.GetPointer() + target_offset,
               g_ca_certificate_public_key_der.data(),
               g_ca_certificate_public_key_der.size_bytes());

        bool found_target_ca = false;

        for (size_t i = 0; i < certificates_count_value; i++) {
            if (infos[i].id ==
                ams::ssl::sf::CaCertificateId::NintendoClass2CAG3) {
                AMS_LOG("PatchCertificates replacing NintendoClass2CAG3 "
                        "index=%zu old_offset=%lx old_size=%lx "
                        "new_offset=%lx new_size=%zu\n",
                        i, infos[i].certificate_data_offset,
                        infos[i].certificate_data_size, target_offset,
                        g_ca_certificate_public_key_der.size_bytes());
                infos[i].certificate_data_offset = target_offset;
                infos[i].certificate_data_size =
                    g_ca_certificate_public_key_der.size_bytes();

                found_target_ca = true;
                break;
            }
        }

        if (!found_target_ca) {
            AMS_LOG("GetCertificates injection failed?! couldn't find the "
                    "target CA in output!\n");
        } else {
            AMS_LOG("PatchCertificates success\n");
        }
    } else {
        AMS_LOG("PatchCertificates skipped: requested ids do not include "
                "NintendoClass2CAG3/All/NewAll ids=%zu\n",
                ids.GetSize());
    }
    R_SUCCEED();
}

Result PatchCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        AMS_LOG("PatchCertificateBufSize inspect id[%zu]=%u\n", i,
                static_cast<u32>(ids[i]));
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All ||
            ids[i] == ams::ssl::sf::CaCertificateId::NewAll) {
            should_inject = true;
            AMS_LOG("PatchCertificateBufSize injection requested by id[%zu]=%u\n",
                    i, static_cast<u32>(ids[i]));
            break;
        }
    }

    if (should_inject) {
        const auto old_size = buffer_size.GetValue();
        const auto der_size = g_ca_certificate_public_key_der.size_bytes();
        buffer_size.SetValue(old_size + der_size);
        AMS_LOG("PatchCertificateBufSize patched old_size=%u der_size=%zu "
                "new_size=%u\n",
                old_size, der_size, buffer_size.GetValue());
    } else {
        AMS_LOG("PatchCertificateBufSize skipped: requested ids do not include "
                "NintendoClass2CAG3/All/NewAll ids=%zu size=%u\n",
                ids.GetSize(), buffer_size.GetValue());
    }
    R_SUCCEED();
}
} // namespace ams::ssl::sf::impl
