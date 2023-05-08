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

@WebServlet(value = "/sqli-00/BenchmarkTest00331")
public class BenchmarkTest00331 extends HttpServlet {

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
    java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00331");

    if (headers != null && headers.hasMoreElements()) {
      param = headers.nextElement(); // just grab first element
    }

    // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = "safe!";
    java.util.HashMap<String, Object> map59781 = new java.util.HashMap<String, Object>();
    map59781.put("keyA-59781", "a_Value"); // put some stuff in the collection
    map59781.put("keyB-59781", param); // put it in a collection
    map59781.put("keyC", "another_Value"); // put some stuff in the collection
    bar = (String) map59781.get("keyB-59781"); // get it back out
    bar = (String) map59781.get("keyA-59781"); // get safe value back out

    @RUntainted String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";

    try {
      java.sql.Connection connection =
          org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
      java.sql.PreparedStatement statement = connection.prepareStatement(sql);
      statement.setString(1, "foo");
      statement.execute();
      org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
    } catch (java.sql.SQLException e) {
      if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
        return;
      } else throw new ServletException(e);
    }
  }
}
