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

@WebServlet(value = "/pathtraver-02/BenchmarkTest02304")
public class BenchmarkTest02304 extends HttpServlet {

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
    boolean flag = true;
    java.util.Enumeration<String> names = request.getParameterNames();
    while (names.hasMoreElements() && flag) {
      String name = (String) names.nextElement();
      String[] values = request.getParameterValues(name);
      if (values != null) {
        for (int i = 0; i < values.length && flag; i++) {
          String value = values[i];
          if (value.equals("BenchmarkTest02304")) {
            param = name;
            flag = false;
          }
        }
      }
    }

    String bar = doSomething(request, param);

    String fileName = null;
    java.io.FileInputStream fis = null;

    try {
      fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
      fis = new java.io.FileInputStream(fileName);
      byte[] b = new byte[1000];
      int size = fis.read(b);
      response
          .getWriter()
          .println(
              "The beginning of file: '"
                  + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName)
                  + "' is:\n\n");
      response
          .getWriter()
          .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(new String(b, 0, size)));
    } catch (Exception e) {
      System.out.println("Couldn't open FileInputStream on file: '" + fileName + "'");
      //			System.out.println("File exception caught and swallowed: " + e.getMessage());
    } finally {
      if (fis != null) {
        try {
          fis.close();
          fis = null;
        } catch (Exception e) {
          // we tried...
        }
      }
    }
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar = "";
    if (param != null) {
      java.util.List<String> valuesList = new java.util.ArrayList<String>();
      valuesList.add("safe");
      valuesList.add(param);
      valuesList.add("moresafe");

      valuesList.remove(0); // remove the 1st safe value

      bar = valuesList.get(0); // get the param value
    }

    return bar;
  }
}
