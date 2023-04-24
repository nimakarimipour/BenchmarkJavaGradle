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
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/pathtraver-02/BenchmarkTest01747")
public class BenchmarkTest01747 extends HttpServlet {

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

    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest01747");

    String bar = new Test().doSomething(request, param);

    // FILE URIs are tricky because they are different between Mac and Windows because of lack
    // of standardization.
    // Mac requires an extra slash for some reason.
    String startURIslashes = "";
    if (System.getProperty("os.name").indexOf("Windows") != -1)
      if (System.getProperty("os.name").indexOf("Windows") != -1) startURIslashes = "/";
      else startURIslashes = "//";

    try {
      java.net.URI fileURI =
          new java.net.URI(
              "file",
              null,
              startURIslashes
                  + org.owasp.benchmark.helpers.Utils.TESTFILES_DIR
                      .replace('\\', java.io.File.separatorChar)
                      .replace(' ', '_')
                  + bar,
              null,
              null);
      java.io.File fileTarget = new java.io.File(fileURI);
      response
          .getWriter()
          .println(
              "Access to file: '"
                  + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileTarget.toString())
                  + "' created.");
      if (fileTarget.exists()) {
        response.getWriter().println(" And file already exists.");
      } else {
        response.getWriter().println(" But file doesn't exist yet.");
      }
    } catch (java.net.URISyntaxException e) {
      throw new ServletException(e);
    }
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      String bar;

      // Simple if statement that assigns constant to bar on true condition
      int num = 86;
      if ((7 * 42) - num > 200) bar = "This_should_always_happen";
      else bar = param;

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
