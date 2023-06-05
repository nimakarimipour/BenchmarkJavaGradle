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

@WebServlet(value = "/cmdi-00/BenchmarkTest00657")
public class BenchmarkTest00657 extends HttpServlet {

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
    String param = scr.getTheParameter("BenchmarkTest00657");
    if (param == null) param = "";

    @RUntainted String bar = "safe!";
    java.util.HashMap<String, Object> map27260 = new java.util.HashMap<String, Object>();
    map27260.put("keyA-27260", "a_Value"); // put some stuff in the collection
    map27260.put("keyB-27260", param); // put it in a collection
    map27260.put("keyC", "another_Value"); // put some stuff in the collection
    bar = (String) map27260.get("keyB-27260"); // get it back out
    bar = (String) map27260.get("keyA-27260"); // get safe value back out

    @RUntainted String cmd = "";
    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
    }

    Runtime r = Runtime.getRuntime();

    try {
      Process p = r.exec(cmd + bar);
      org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
    } catch (IOException e) {
      System.out.println("Problem executing cmdi - TestCase");
      response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
      return;
    }
  }
}
