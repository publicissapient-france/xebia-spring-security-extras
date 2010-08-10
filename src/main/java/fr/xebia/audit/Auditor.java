/*
 * Copyright 2008-2009 Xebia and the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.xebia.audit;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Util to write audit information.
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class Auditor {

    private final static Logger auditLogger = LoggerFactory.getLogger("fr.xebia.audit");

    private static SimpleDateFormat dateFormatPrototype = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");

    /**
     * <p>
     * Emmits the audit message : <code>
     * "$date{yyyy-MM-dd'T'HH:mm:ss.SSSZZ} ${message} by ${spring-security-user}|anonymous [coming from ${remote-address}]"</code>.
     * <p>
     * <p>
     * If the Spring Security authentication is <code>null</code>, 'anonymous'
     * is emmitted.
     * </p>
     * <p>
     * If the Spring Security authentication details are
     * {@link WebAuthenticationDetails}, the incoming
     * {@link WebAuthenticationDetails#getRemoteAddress()} is emmitted.
     * </p>
     * 
     * @param message
     *            message to audit
     * @see SecurityContextHolder#getContext()
     */
    public static void audit(String message) {
        if (message == null) {
            message = "";
        }
        StringBuilder msg = new StringBuilder(40 + message.length());

        SimpleDateFormat simpleDateFormat = (SimpleDateFormat) dateFormatPrototype.clone();
        msg.append(simpleDateFormat.format(new Date()));

        msg.append(" ").append(message).append(" by ");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            msg.append("anonymous");
        } else {
            msg.append(authentication.getName());
            if (authentication.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
                msg.append(" coming from " + details.getRemoteAddress());
            }
        }
        auditLogger.info(msg.toString());
    }
}
