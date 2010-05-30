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
package fr.xebia.ipbanner;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** This filter checks if the Http response and ban IP address in case of authentication error.
 * If the Http Response status is 401 (unauthorized), 403 (Forbidden) or custom defined response, the IP address is added to
 * the list of failed attempts.
 * If the number of failed attempts for the client IP address is greater than the number of maximum retry, the connection
 * attempt is rejected (returns 403 error).
 *
 * The failureResponseStatusCodes filter property defines a comma separated list of Http Response status that implies a
 * failed connection attempt.
 *
 * The maxRetry property defines the maximum number of failed attempts to connect (default is 10).
 *
 * Example of web.xml :
 * <filter>
 *   <filter-name>IP Banner</filter-name>
 *   <display-name>IP Banner</display-name>
 *   <filter-class>fr.xebia.ipbanner.IpBannerFilter</filter-class>
 *   <init-param>
 *     <param-name>failureResponseStatusCodes</param-name>
 *     <param-value>401,403</param-value>
 *   </init-param
 *   <init-param>
 *     <param-name>failureRequestAttributeName</param-name>
 *     <param-value>IpBannerFilter.failure</param-value>
 *   </init-param>>
 *   <init-param>
 *     <param-name>maxRetry</param-name>
 *     <param-value>10</param-value>
 *   </init-param>
 *   <init-param>
 *     <param-name>banTimeInSecond</param-name>
 *     <param-value>60</param-value>
 *   </init-param>
 * </filter>
 *
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class IpBannerFilter implements Filter {

    /** Wrap the HttpServletResponse to get the http response status.
     */
    public static class XHttpServletResponse extends HttpServletResponseWrapper {

        /**
         * <p>
         * Response status.
         * </p>
         * <p>
         * We store it because {@link HttpServletResponse} only exposes setters
         * but no getter.
         * </p>
         */
        private int status = HttpServletResponse.SC_OK;

        public XHttpServletResponse(HttpServletResponse response) {
            super(response);
        }

        public int getStatus() {
            return status;
        }

        @Override
        public void sendError(int sc) throws IOException {
            this.status = sc;
            super.sendError(sc);
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            this.status = sc;
            super.sendError(sc, msg);
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            this.status = HttpServletResponse.SC_FOUND;
            super.sendRedirect(location);
        }

        @Override
        public void setStatus(int sc) {
            this.status = sc;
            super.setStatus(sc);
        }

        @Override
        public void setStatus(int sc, String sm) {
            this.status = sc;
            super.setStatus(sc, sm);
        }
    }

    /**
     * {@link Pattern} for a comma delimited string that support whitespace
     * characters
     */
    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");

    public static final String FAILURE_REQUEST_ATTRIBUTE_NAME = "failureRequestAttributeName";

    public static final String FAILURE_RESPONSE_STATUS_CODES = "failureResponseStatusCodes";

    public static final String MAX_RETRY_PARAMETER = "maxRetry";

    private static final int DEFAULT_MAX_RETRY = 10;

    private static final String BAN_TIME_PARAMETER = "banTimeInSecond";

    private static final int DEFAULT_BAN_TIME = 60; 

    /**
     * Convert a comma delimited list of numbers into an <tt>int[]</tt>.
     * 
     * @param commaDelimitedInts
     *            can be <code>null</code>
     * @return never <code>null</code> array
     */
    protected static int[] commaDelimitedListToIntArray(String commaDelimitedInts) {
        String[] intsAsStrings = commaDelimitedListToStringArray(commaDelimitedInts);
        int[] ints = new int[intsAsStrings.length];
        for (int i = 0; i < intsAsStrings.length; i++) {
            String intAsString = intsAsStrings[i];
            try {
                ints[i] = Integer.parseInt(intAsString);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Exception parsing number '" + i + "' (zero based) of comma delimited list '"
                        + commaDelimitedInts + "'");
            }
        }
        return ints;
    }

    /**
     * Convert a given comma delimited list of strings into an array of String
     * 
     * @return array of patterns (non <code>null</code>)
     */
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedValuesPattern
                .split(commaDelimitedStrings);
    }

    /**
     * Convert an array of ints into a comma delimited string
     */
    protected static String intsToCommaDelimitedString(int[] ints) {
        if (ints == null) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < ints.length; i++) {
            result.append(ints[i]);
            if (i < (ints.length - 1)) {
                result.append(", ");
            }
        }
        return result.toString();
    }

    private String failureRequestAttributeName = IpBannerFilter.class.getName() + ".failure";

    private int[] failureResponseStatusCodes = new int[] { HttpServletResponse.SC_UNAUTHORIZED, HttpServletResponse.SC_FORBIDDEN };

    /**
     * visible for test
     */
    protected IpBanner ipBanner;

    protected final Logger logger = LoggerFactory.getLogger(IpBannerFilter.class);

    @Override
    public void destroy() {
        try {
            ipBanner.destroy();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        if (req instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;
            String ip = req.getRemoteAddr();

            if (ipBanner.isIpBanned(ip)) {

                StringBuilder msg = new StringBuilder("Reject request ");
                msg.append(request.getMethod()).append(" ");
                msg.append(request.getRequestURL());
                if (request.getQueryString() != null) {
                    msg.append("?").append(request.getQueryString());
                }
                msg.append(" emmitted by ip ").append(ip);
                logger.info(msg.toString());

                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Banned ip");
                return;
            }

            XHttpServletResponse xresponse = new XHttpServletResponse(response);
            try {
                chain.doFilter(request, xresponse);
            } finally {
                boolean isFailedAuthentication = isFailedAuthentication(request, xresponse);
                if (isFailedAuthentication) {
                    ipBanner.incrementFailureCounter(ip);
                }
            }

        } else {
            chain.doFilter(req, res);

        }
    }

    public String getFailureRequestAttributeName() {
        return failureRequestAttributeName;
    }

    public int getIntParameter(FilterConfig filterConfig, String parameterName, int defaultValue) {
        String value = filterConfig.getInitParameter(parameterName);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new RuntimeException(String.format("Exception parsing %s value '%s' as an integer.", parameterName, value));
        }
    }

    public String getFailureResponseStatusCodes() {
        return intsToCommaDelimitedString(failureResponseStatusCodes);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        String comaDelimitedResponseStatusCodes = filterConfig.getInitParameter(FAILURE_RESPONSE_STATUS_CODES);
        if (comaDelimitedResponseStatusCodes != null) {
            setFailureResponseResponseStatusCodes(comaDelimitedResponseStatusCodes);
        }

        // Keep default value if not defined
        if (filterConfig.getInitParameter(FAILURE_REQUEST_ATTRIBUTE_NAME) != null) {
            setFailureRequestAttributeName(filterConfig.getInitParameter(FAILURE_REQUEST_ATTRIBUTE_NAME));
        }

        ipBanner = new IpBanner();

        ipBanner.initialize();

        ipBanner.setMaxRetry(getIntParameter(filterConfig, MAX_RETRY_PARAMETER, DEFAULT_MAX_RETRY));
        ipBanner.setBanTimeInSeconds(getIntParameter(filterConfig, BAN_TIME_PARAMETER, DEFAULT_BAN_TIME));

    }

    protected boolean isFailedAuthentication(HttpServletRequest request, XHttpServletResponse xresponse) {
        for (int failureStatusCode : this.failureResponseStatusCodes) {
            if (xresponse.getStatus() == failureStatusCode) {
                return true;
            }
        }
        if (request.getAttribute(failureRequestAttributeName) != null) {
            return true;
        }
        return false;
    }

    public void setFailureRequestAttributeName(String failureRequestAttributeName) {
        this.failureRequestAttributeName = failureRequestAttributeName;
    }

    public void setFailureResponseResponseStatusCodes(int[] failureStatusCodes) {
        this.failureResponseStatusCodes = failureStatusCodes;
    }

    public void setFailureResponseResponseStatusCodes(String commaDelimitedStatusCodes) {
        setFailureResponseResponseStatusCodes(commaDelimitedListToIntArray(commaDelimitedStatusCodes));
    }

    public void setFailureResponseStatusCodes(int[] failureResponseStatusCodes) {
        this.failureResponseStatusCodes = failureResponseStatusCodes;
    }

}
