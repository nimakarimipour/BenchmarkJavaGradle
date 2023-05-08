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
import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;

@WebServlet(value = "/sqli-04/BenchmarkTest02173")
public class BenchmarkTest02173 extends HttpServlet {

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

    String param = request.getParameter("BenchmarkTest02173");
    if (param == null) param = "";

    String bar = doSomething(request, param);

    @RUntainted String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";

    try {
      java.sql.Connection connection =
          org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
      java.sql.PreparedStatement statement =
          connection.prepareStatement(
              sql, java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY);
      statement.setString(1, "foo");
      statement.execute();
      org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
    } catch (java.sql.SQLException e) {
      if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
        return;
      } else throw new ServletException(e);
    }
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar;
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
}
