/**
 *
 * Copyright © 2014 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kontalk.certgen;

/** Stripped version of Smack's XmppStringUtils. */
public class XmppStringUtils {

    /**
     * Returns the domain of an XMPP address (JID). For example, for the address "user@xmpp.org/Resource", "xmpp.org"
     * would be returned. If <code>jid</code> is <code>null</code>, then this method returns also <code>null</code>. If
     * the input String is no valid JID or has no domainpart, then this method will return the empty String.
     *
     * @param jid
     *            the XMPP address to parse.
     * @return the domainpart of the XMPP address, the empty String or <code>null</code>.
     */
    public static String parseDomain(String jid) {
        if (jid == null) return null;

        int atIndex = jid.indexOf('@');
        // If the String ends with '@', return the empty string.
        if (atIndex + 1 > jid.length()) {
            return "";
        }
        int slashIndex = jid.indexOf('/');
        if (slashIndex > 0) {
            // 'local@domain.foo/resource' and 'local@domain.foo/res@otherres' case
            if (slashIndex > atIndex) {
                return jid.substring(atIndex + 1, slashIndex);
                // 'domain.foo/res@otherres' case
            } else {
                return jid.substring(0, slashIndex);
            }
        } else {
            return jid.substring(atIndex + 1);
        }
    }


}
