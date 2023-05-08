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

import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/trustbound-01/BenchmarkTest01960")
public class BenchmarkTest01960 extends HttpServlet {

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
    if (request.getHeader("BenchmarkTest01960") != null) {
      param = request.getHeader("BenchmarkTest01960");
    }

    // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    @RUntainted String bar = doSomething(request, param);

    // javax.servlet.http.HttpSession.setAttribute(java.lang.String,java.lang.Object^)
    request.getSession().setAttribute("userid", bar);

    response
        .getWriter()
        .println(
            "Item: 'userid' with value: '"
                + org.owasp.benchmark.helpers.Utils.encodeForHTML(bar)
                + "' saved in session.");
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar = param;
    if (param != null && param.length() > 1) {
      bar = param.substring(0, param.length() - 1);
    }

    return bar;
  }
}
