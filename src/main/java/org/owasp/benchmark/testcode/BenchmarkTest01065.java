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

import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/cmdi-01/BenchmarkTest01065")
public class BenchmarkTest01065 extends HttpServlet {

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

    @RUntainted String param = "";
    if (request.getHeader("BenchmarkTest01065") != null) {
      param = request.getHeader("BenchmarkTest01065");
    }

    // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    @RUntainted String bar = new Test().doSomething(request, param);

    @RUntainted String cmd = "";
    String a1 = "";
    String a2 = "";
    @RUntainted String[] args = null;
    String osName = System.getProperty("os.name");

    if (osName.indexOf("Windows") != -1) {
      a1 = "cmd.exe";
      a2 = "/c";
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
      args = new String[] {a1, a2, cmd, bar};
    } else {
      a1 = "sh";
      a2 = "-c";
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("ping -c1 ");
      args = new String[] {a1, a2, cmd + bar};
    }

    Runtime r = Runtime.getRuntime();

    try {
      Process p = r.exec(args);
      org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
    } catch (IOException e) {
      System.out.println("Problem executing cmdi - TestCase");
      response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
      return;
    }
  } // end doPost

  private class Test {

    public @RUntainted String doSomething(HttpServletRequest request, @RUntainted String param)
        throws ServletException, IOException {

      @RUntainted String bar;

      // Simple if statement that assigns constant to bar on true condition
      int num = 86;
      if ((7 * 42) - num > 200) bar = "This_should_always_happen";
      else bar = param;

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
