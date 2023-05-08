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

@WebServlet(value = "/sqli-01/BenchmarkTest00837")
public class BenchmarkTest00837 extends HttpServlet {

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
    String paramval = "BenchmarkTest00837" + "=";
    int paramLoc = -1;
    if (queryString != null) paramLoc = queryString.indexOf(paramval);
    if (paramLoc == -1) {
      response
          .getWriter()
          .println(
              "getQueryString() couldn't find expected parameter '"
                  + "BenchmarkTest00837"
                  + "' in query string.");
      return;
    }

    String param =
        queryString.substring(
            paramLoc + paramval.length()); // 1st assume "BenchmarkTest00837" param is last
    // parameter in query string.
    // And then check to see if its in the middle of the query string and if so, trim off what
    // comes after.
    int ampersandLoc = queryString.indexOf("&", paramLoc);
    if (ampersandLoc != -1) {
      param = queryString.substring(paramLoc + paramval.length(), ampersandLoc);
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = "safe!";
    java.util.HashMap<String, Object> map5936 = new java.util.HashMap<String, Object>();
    map5936.put("keyA-5936", "a_Value"); // put some stuff in the collection
    map5936.put("keyB-5936", param); // put it in a collection
    map5936.put("keyC", "another_Value"); // put some stuff in the collection
    bar = (String) map5936.get("keyB-5936"); // get it back out
    bar = (String) map5936.get("keyA-5936"); // get safe value back out

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
  }
}
