/**
 * OWASP Benchmark Project v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/xss-03/BenchmarkTest02049")
public class BenchmarkTest02049 extends HttpServlet {

  private static final long serialVersionUID = 1L;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    doPost(request, response);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");

    String param = "";
    java.util.Enumeration<String> headers = request.getHeaders("Referer");

    if (headers != null && headers.hasMoreElements()) {
      param = headers.nextElement(); // just grab first element
    }

    // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = doSomething(request, param);

    response.setHeader("X-XSS-Protection", "0");
    Object[] obj = {"a", bar};
    response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);

    return bar;
  }
}