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

@WebServlet(value = "/pathtraver-01/BenchmarkTest01033")
public class BenchmarkTest01033 extends HttpServlet {

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
    if (request.getHeader("BenchmarkTest01033") != null) {
      param = request.getHeader("BenchmarkTest01033");
    }

    // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = new Test().doSomething(request, param);

    String fileName = null;
    java.io.FileOutputStream fos = null;

    try {
      fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;

      fos = new java.io.FileOutputStream(new java.io.File(fileName));
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
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      org.owasp.benchmark.helpers.ThingInterface thing =
          org.owasp.benchmark.helpers.ThingFactory.createThing();
      String bar = thing.doSomething(param);

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
