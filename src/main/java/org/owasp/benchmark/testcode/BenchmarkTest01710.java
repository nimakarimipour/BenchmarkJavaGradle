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

@WebServlet(value = "/trustbound-01/BenchmarkTest01710")
public class BenchmarkTest01710 extends HttpServlet {

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

    String queryString = request.getQueryString();
    String paramval = "BenchmarkTest01710" + "=";
    int paramLoc = -1;
    if (queryString != null) paramLoc = queryString.indexOf(paramval);
    if (paramLoc == -1) {
      response
          .getWriter()
          .println(
              "getQueryString() couldn't find expected parameter '"
                  + "BenchmarkTest01710"
                  + "' in query string.");
      return;
    }

    String param =
        queryString.substring(
            paramLoc + paramval.length()); // 1st assume "BenchmarkTest01710" param is last
    // parameter in query string.
    // And then check to see if its in the middle of the query string and if so, trim off what
    // comes after.
    int ampersandLoc = queryString.indexOf("&", paramLoc);
    if (ampersandLoc != -1) {
      param = queryString.substring(paramLoc + paramval.length(), ampersandLoc);
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = new Test().doSomething(request, param);

    // javax.servlet.http.HttpSession.setAttribute(java.lang.String,java.lang.Object^)
    request.getSession().setAttribute("userid", bar);

    response
        .getWriter()
        .println(
            "Item: 'userid' with value: '"
                + org.owasp.benchmark.helpers.Utils.encodeForHTML(bar)
                + "' saved in session.");
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      String bar;

      // Simple ? condition that assigns param to bar on false condition
      int num = 106;

      bar = (7 * 42) - num > 200 ? "This should never happen" : param;

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
