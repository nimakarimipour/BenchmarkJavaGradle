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

@WebServlet(value = "/pathtraver-00/BenchmarkTest00785")
public class BenchmarkTest00785 extends HttpServlet {

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
    String paramval = "BenchmarkTest00785" + "=";
    int paramLoc = -1;
    if (queryString != null) paramLoc = queryString.indexOf(paramval);
    if (paramLoc == -1) {
      response
          .getWriter()
          .println(
              "getQueryString() couldn't find expected parameter '"
                  + "BenchmarkTest00785"
                  + "' in query string.");
      return;
    }

    String param =
        queryString.substring(
            paramLoc + paramval.length()); // 1st assume "BenchmarkTest00785" param is last
    // parameter in query string.
    // And then check to see if its in the middle of the query string and if so, trim off what
    // comes after.
    int ampersandLoc = queryString.indexOf("&", paramLoc);
    if (ampersandLoc != -1) {
      param = queryString.substring(paramLoc + paramval.length(), ampersandLoc);
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = "safe!";
    java.util.HashMap<String, Object> map59480 = new java.util.HashMap<String, Object>();
    map59480.put("keyA-59480", "a-Value"); // put some stuff in the collection
    map59480.put("keyB-59480", param); // put it in a collection
    map59480.put("keyC", "another-Value"); // put some stuff in the collection
    bar = (String) map59480.get("keyB-59480"); // get it back out

    String fileName = null;
    java.io.FileOutputStream fos = null;

    try {
      fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;

      fos = new java.io.FileOutputStream(fileName, false);
      response
          .getWriter()
          .println(
              "Now ready to write to file: "
                  + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

    } catch (Exception e) {
      System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
      //			System.out.println("File exception caught and swallowed: " + e.getMessage());
    } finally {
      if (fos != null) {
        try {
          fos.close();
          fos = null;
        } catch (Exception e) {
          // we tried...
        }
      }
    }
  }
}
