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

@WebServlet(value = "/cmdi-01/BenchmarkTest01353")
public class BenchmarkTest01353 extends HttpServlet {

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

    java.util.@RUntainted Map<@RUntainted String, @RUntainted String[]> map = request.getParameterMap();
    @RUntainted String param = "";
    if (!map.isEmpty()) {
      @RUntainted String[] values = map.get("BenchmarkTest01353");
      if (values != null) param = values[0];
    }

    @RUntainted String bar = new Test().doSomething(request, param);

    java.util.@RUntainted List<@RUntainted String> argList = new java.util.ArrayList<String>();

    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      argList.add("cmd.exe");
      argList.add("/c");
    } else {
      argList.add("sh");
      argList.add("-c");
    }
    argList.add("echo " + bar);

    ProcessBuilder pb = new ProcessBuilder();

    pb.command(argList);

    try {
      Process p = pb.start();
      org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
    } catch (IOException e) {
      System.out.println(
          "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
      throw new ServletException(e);
    }
  } // end doPost

  private class Test {

    public @RUntainted String doSomething(HttpServletRequest request, @RUntainted String param)
        throws ServletException, IOException {

      @RUntainted String bar;
      String guess = "ABC";
      char switchTarget = guess.charAt(1); // condition 'B', which is safe

      // Simple case statement that assigns param to bar on conditions 'A', 'C', or 'D'
      switch (switchTarget) {
        case 'A':
          bar = param;
          break;
        case 'B':
          bar = "bob";
          break;
        case 'C':
        case 'D':
          bar = param;
          break;
        default:
          bar = "bob's your uncle";
          break;
      }

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
