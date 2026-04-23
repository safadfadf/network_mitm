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
#include "networkmitm_ssl_service_impl.hpp"
#include "networkmitm_utils.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslServiceImpl::CreateContext(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out) {
    NETWORK_MITM_VLOG("SSL CreateContext tid=%lx version=%u client_pid=%lx dump=%s "
            "disable_verify=%s\n",
            static_cast<u64>(m_client_info.program_id), static_cast<u32>(version),
            static_cast<u64>(client_pid.GetValue()),
            BoolString(m_should_dump_traffic),
            BoolString(g_should_disable_ssl_verification));

    // If we aren't mitm the traffic or disabling verifications, we don't want
    // to control the sub objects to reduce overhead.
    if (!m_should_dump_traffic && !g_should_disable_ssl_verification) {
        NETWORK_MITM_VLOG("SSL CreateContext forwarding to original session\n");
        return sm::mitm::ResultShouldForwardToSession();
    }

    Service out_tmp;
    Result rc = sslCreateContext_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));
    LogResult("sslCreateContext_sfMitm", rc);
    R_TRY(rc);

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};
    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslContext, SslContextImpl>(
            std::make_unique<::Service>(out_tmp), m_client_info,
            m_should_dump_traffic, m_link_type),
        target_object_id);

    R_SUCCEED();
}

Result SslServiceImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    NETWORK_MITM_VLOG("SSL GetCertificates tid=%lx ids=%zu out_size=%zu\n",
            static_cast<u64>(m_client_info.program_id), ids.GetSize(),
            certificates.GetSize());
    Result rc = sslGetCertificates_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        certificates_count.GetPointer(), certificates.GetPointer(),
        certificates.GetSize());
    LogResult("sslGetCertificates_sfMitm", rc);
    R_TRY(rc);

    rc = PatchCertificates(ids, certificates_count, certificates);
    LogResult("PatchCertificates", rc);
    R_TRY(rc);

    R_SUCCEED();
}

Result SslServiceImpl::GetCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    NETWORK_MITM_VLOG("SSL GetCertificateBufSize tid=%lx ids=%zu\n",
            static_cast<u64>(m_client_info.program_id), ids.GetSize());
    Result rc = sslGetCertificateBufSize_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        buffer_size.GetPointer());
    LogResult("sslGetCertificateBufSize_sfMitm", rc);
    R_TRY(rc);

    rc = PatchCertificateBufSize(ids, buffer_size);
    LogResult("PatchCertificateBufSize", rc);
    R_TRY(rc);

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
