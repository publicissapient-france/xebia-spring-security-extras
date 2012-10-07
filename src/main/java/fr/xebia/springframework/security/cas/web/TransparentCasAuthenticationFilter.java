/*
 * Copyright 2008-2012 Xebia and the original author or authors.
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
package fr.xebia.springframework.security.cas.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.util.WebUtils;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>If <code>CAS_ACTIVE</code> cookie is set to <code>true</code>, triggers an authentication roundtrip to the CAS server.</p>
 * <p>Roundtrip to the CAS server is triggered:
 * <ul>
 * <li>when user not authenticated (including {@link AnonymousAuthenticationToken})
 * or authenticated in a remember-me mode {@link RememberMeAuthenticationToken}</li>,
 * <li>throwing a {@link org.springframework.security.authentication.InsufficientAuthenticationException}.</li>
 * </ul></p>
 * <p>A protection against infinite redirection is managed with the <code>TRANSPARENT_AUTHENTICATION_IN_ACTION</code> session attribute.</p>
 *
 * @author <a href="mailto:cleclerc@xebia.fr">Cyrille Le Clerc</a>
 */
public class TransparentCasAuthenticationFilter implements Filter {

    private final String AUTHENTICATION_IN_ACTION_ATTRIBUTE = "TRANSPARENT_AUTHENTICATION_IN_ACTION";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {


        boolean authenticationInAction = Boolean.TRUE.equals(WebUtils.getSessionAttribute(request, AUTHENTICATION_IN_ACTION_ATTRIBUTE));

        boolean ssoSessionExists = isSsoSessionExists(request);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean stronglyAuthenticatedUser =
                authentication != null &&
                        !(authentication instanceof AnonymousAuthenticationToken) &&
                        !(authentication instanceof RememberMeAuthenticationToken);

        if (stronglyAuthenticatedUser) {
            if (authenticationInAction) {
                request.getSession().removeAttribute(AUTHENTICATION_IN_ACTION_ATTRIBUTE);
                logger.debug("StronglyAuthenticatedUser just coming from a transparent authentication, continue '{}'", request.getRequestURI());
            } else {
                logger.debug("StronglyAuthenticatedUser, continue '{}'", request.getRequestURI());
            }
        } else if (ssoSessionExists) {
            if (authenticationInAction) {
                logger.debug("Anonymous/RememberMe user already in transparent authentication process, continue '{}'", request.getRequestURI());
            } else {
                logger.debug("Anonymous/RememberMe user with maybe active SSO Session, trigger a Transparent Login via Spring Security '{}'", request.getRequestURI());
                request.getSession().setAttribute(AUTHENTICATION_IN_ACTION_ATTRIBUTE, Boolean.TRUE);
                throw new InitiateTransparentAuthenticationException("Trigger authentication, anonymous user with CAS_ACTIVE " +
                        "cookie may have an active CAS Session : " + authentication);
            }
        } else {
            logger.debug("Anonymous/RememberMe user with NO active SSO Session, continue '{}'", request.getRequestURI());
        }

        chain.doFilter(request, response);
    }

    protected boolean isSsoSessionExists(HttpServletRequest request) {
        Cookie casPublicSessionCookie = WebUtils.getCookie(request, "CAS_ACTIVE");

        return casPublicSessionCookie != null && "true".equalsIgnoreCase(casPublicSessionCookie.getValue());
    }

    @Override
    public void destroy() {
    }
}
