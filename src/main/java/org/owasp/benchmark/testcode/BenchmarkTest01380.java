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
import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;

@WebServlet(value = "/sqli-02/BenchmarkTest01380")
public class BenchmarkTest01380 extends HttpServlet {

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

    java.util.Map<String, String[]> map = request.getParameterMap();
    String param = "";
    if (!map.isEmpty()) {
      String[] values = map.get("BenchmarkTest01380");
      if (values != null) param = values[0];
    }

    String bar = new Test().doSomething(request, param);

    @RUntainted String sql = "{call " + bar + "}";

    try {
      java.sql.Connection connection =
          org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
      java.sql.CallableStatement statement =
          connection.prepareCall(
              sql,
              java.sql.ResultSet.TYPE_FORWARD_ONLY,
              java.sql.ResultSet.CONCUR_READ_ONLY,
              java.sql.ResultSet.CLOSE_CURSORS_AT_COMMIT);
      java.sql.ResultSet rs = statement.executeQuery();
      org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
    } catch (java.sql.SQLException e) {
      if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
        return;
      } else throw new ServletException(e);
    }
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      String bar;

      // Simple ? condition that assigns constant to bar on true condition
      int num = 106;

      bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
