/*
 * Copyright (C) 2019 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "config.h"
#import "CCIDService.h"

#if ENABLE(WEB_AUTHN)

#import "CtapCCIDDriver.h"
#import "CCIDConnection.h"
#import <wtf/BlockPtr.h>
#import <wtf/RetainPtr.h>
#import <wtf/RunLoop.h>
#import <CryptoTokenKit/TKSmartCard.h>
#import <WebCore/AuthenticatorTransport.h>

namespace WebKit {

CCIDService::CCIDService(Observer& observer)
    : FidoService(observer)
    , m_restartTimer(RunLoop::main(), this, &CCIDService::platformStartDiscovery)
{
}

CCIDService::~CCIDService()
{
}

void CCIDService::didConnectTag()
{
    auto connection = m_connection;
    getInfo(WTF::makeUnique<CtapCcidDriver>(connection.releaseNonNull(), m_connection->contactless() ? WebCore::AuthenticatorTransport::Nfc : WebCore::AuthenticatorTransport::SmartCard));
}

void CCIDService::startDiscoveryInternal()
{
    platformStartDiscovery();
}

void CCIDService::restartDiscoveryInternal()
{
    if (m_connection)
        m_connection->stop();
    m_restartTimer.startOneShot(1_s); // Magic number to give users enough time for reactions.
}

void CCIDService::platformStartDiscovery()
{
    for (NSString *slotName : [[TKSmartCardSlotManager defaultManager] slotNames]) {
        WTFLogAlways("see slot: %s", slotName);
        [[TKSmartCardSlotManager defaultManager] getSlotWithName:slotName reply:makeBlockPtr([this](TKSmartCardSlot * _Nullable slot) mutable {
            auto* smartCard = [slot makeSmartCard];
            if (smartCard) {
                WTFLogAlways("made card");
                callOnMainRunLoop([this, smartCard = retainPtr(smartCard)] () mutable {
                    auto connection = CCIDConnection::create(WTFMove(smartCard), *this);
                    m_connection = WTFMove(connection);
                });
            } else {
                m_restartTimer.startOneShot(1_s); // Magic number to give users enough time for reactions.
            }
        }).get()];
    }
}

} // namespace WebKit

#endif // ENABLE(WEB_AUTHN)
