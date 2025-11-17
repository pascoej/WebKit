/*
 * Copyright (C) 2025 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "InspectorInitiatorUtilities.h"

#include "DocumentInlines.h"
#include "InspectorDOMAgent.h"
#include "InstrumentingAgents.h"
#include "JSExecState.h"
#include "ResourceRequest.h"
#include "ScriptableDocumentParser.h"
#include <JavaScriptCore/ScriptCallStack.h>
#include <JavaScriptCore/ScriptCallStackFactory.h>

namespace WebCore {

namespace InspectorInitiatorUtilities {

Ref<Inspector::Protocol::Network::Initiator> buildInitiatorObject(Document* document, const ResourceRequest* resourceRequest, InstrumentingAgents* instrumentingAgents)
{
    // FIXME: Worker support.
    if (!isMainThread()) {
        return Inspector::Protocol::Network::Initiator::create()
            .setType(Inspector::Protocol::Network::Initiator::Type::Other)
            .release();
    }

    RefPtr<Inspector::Protocol::Network::Initiator> initiatorObject;

    Ref<ScriptCallStack> stackTrace = createScriptCallStack(JSExecState::currentState());
    if (stackTrace->size() > 0) {
        initiatorObject = Inspector::Protocol::Network::Initiator::create()
            .setType(Inspector::Protocol::Network::Initiator::Type::Script)
            .release();
        initiatorObject->setStackTrace(stackTrace->buildInspectorObject());
    } else if (document && document->scriptableDocumentParser()) {
        initiatorObject = Inspector::Protocol::Network::Initiator::create()
            .setType(Inspector::Protocol::Network::Initiator::Type::Parser)
            .release();
        initiatorObject->setUrl(document->url().string());
        initiatorObject->setLineNumber(document->scriptableDocumentParser()->textPosition().m_line.oneBasedInt());
    }

    if (instrumentingAgents && resourceRequest) {
        auto domAgent = instrumentingAgents->persistentDOMAgent();
        if (domAgent) {
            if (auto inspectorInitiatorNodeIdentifier = resourceRequest->inspectorInitiatorNodeIdentifier()) {
                if (!initiatorObject) {
                    initiatorObject = Inspector::Protocol::Network::Initiator::create()
                        .setType(Inspector::Protocol::Network::Initiator::Type::Other)
                        .release();
                }

                initiatorObject->setNodeId(*inspectorInitiatorNodeIdentifier);
            }
        }
    }

    if (initiatorObject)
        return initiatorObject.releaseNonNull();

    return Inspector::Protocol::Network::Initiator::create()
        .setType(Inspector::Protocol::Network::Initiator::Type::Other)
        .release();
}

} // namespace InspectorInitiatorUtilities

} // namespace WebCore