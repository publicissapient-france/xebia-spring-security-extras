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
package fr.xebia.fail2ban;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.FilterHolder;
import org.mortbay.jetty.servlet.ServletHolder;

public class IpBannerFilterTest {

    public static final String TEMP_DIR = System.getProperty("java.io.tmpdir");

    /**
     * Test {@link IpBannerFilter} in Jetty standalone server
     */
    public void testWithTomcatServer() throws Exception {

        IpBannerFilter ipBannerFilter = new IpBannerFilter();

        // SETUP
        int port = 6666;
        Server server = new Server(port);
        Context context = new Context(server, "/", Context.SESSIONS);

        context.addFilter(new FilterHolder(ipBannerFilter), "/*", Handler.REQUEST);

        HttpServlet status200Servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                response.getWriter().print("Hello world");
            }
        };
        context.addServlet(new ServletHolder(status200Servlet), "/200");

        HttpServlet status401Servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        };
        context.addServlet(new ServletHolder(status401Servlet), "/401");
        
        HttpServlet status403Servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        };
        context.addServlet(new ServletHolder(status403Servlet), "/403");

        server.start();
        
        HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://localhost:" + port + "/200").openConnection();

        
        server.stop();

    }
}
