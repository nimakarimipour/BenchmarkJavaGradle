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

@WebServlet(value = "/pathtraver-02/BenchmarkTest02381")
public class BenchmarkTest02381 extends HttpServlet {

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
    String param = scr.getTheParameter("BenchmarkTest02381");
    if (param == null) param = "";

    String bar = doSomething(request, param);

    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;

    try (
    // Create the file first so the test won't throw an exception if it doesn't exist.
    // Note: Don't actually do this because this method signature could cause a tool to find
    // THIS file constructor
    // as a vuln, rather than the File signature we are trying to actually test.
    // If necessary, just run the benchmark twice. The 1st run should create all the necessary
    // files.
    // new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar).createNewFile();

    java.io.FileOutputStream fos =
        new java.io.FileOutputStream(new java.io.FileInputStream(fileName).getFD()); ) {
      response
          .getWriter()
          .println(
              "Now ready to write to file: "
                  + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

    } catch (Exception e) {
      System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
    }
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar = "safe!";
    java.util.HashMap<String, Object> map75774 = new java.util.HashMap<String, Object>();
    map75774.put("keyA-75774", "a_Value"); // put some stuff in the collection
    map75774.put("keyB-75774", param); // put it in a collection
    map75774.put("keyC", "another_Value"); // put some stuff in the collection
    bar = (String) map75774.get("keyB-75774"); // get it back out
    bar = (String) map75774.get("keyA-75774"); // get safe value back out

    return bar;
  }
}
