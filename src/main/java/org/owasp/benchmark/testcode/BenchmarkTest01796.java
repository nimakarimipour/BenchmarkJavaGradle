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
import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;

@WebServlet(value = "/cmdi-02/BenchmarkTest01796")
public class BenchmarkTest01796 extends HttpServlet {

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
    String param = scr.getTheValue("BenchmarkTest01796");

    @RUntainted String bar = new Test().doSomething(request, param);

    String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
            this.getClass().getClassLoader());
    @RUntainted String[] args = {cmd};
    @RUntainted String[] argsEnv = {bar};

    Runtime r = Runtime.getRuntime();

    try {
      Process p = r.exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")));
      org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
    } catch (IOException e) {
      System.out.println("Problem executing cmdi - TestCase");
      response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
      return;
    }
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      String bar;
      String guess = "ABC";
      char switchTarget = guess.charAt(2);

      // Simple case statement that assigns param to bar on conditions 'A', 'C', or 'D'
      switch (switchTarget) {
        case 'A':
          bar = param;
          break;
        case 'B':
          bar = "bobs_your_uncle";
          break;
        case 'C':
        case 'D':
          bar = param;
          break;
        default:
          bar = "bobs_your_uncle";
          break;
      }

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
