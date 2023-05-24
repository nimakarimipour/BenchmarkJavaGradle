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

@WebServlet(value = "/sqli-04/BenchmarkTest02182")
public class BenchmarkTest02182 extends HttpServlet {

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

    String param = request.getParameter("BenchmarkTest02182");
    if (param == null) param = "";

    String bar = doSomething(request, param);

    String sql = "SELECT TOP 1 userid from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
    try {
      java.util.Map<String, Object> results =
          org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForMap(sql);
      response.getWriter().println("Your results are: ");

      //		System.out.println("Your results are");
      response
          .getWriter()
          .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(results.toString()));
      //		System.out.println(results.toString());
    } catch (org.springframework.dao.EmptyResultDataAccessException e) {
      response
          .getWriter()
          .println(
              "No results returned for query: "
                  + org.owasp.esapi.ESAPI.encoder().encodeForHTML(sql));
    } catch (org.springframework.dao.DataAccessException e) {
      if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
      } else throw new ServletException(e);
    }
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar = "";
    if (param != null) {
      bar =
          new String(
              org.apache.commons.codec.binary.Base64.decodeBase64(
                  org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));
    }

    return bar;
  }
}
