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

@WebServlet(value = "/weakrand-01/BenchmarkTest00506")
public class BenchmarkTest00506 extends HttpServlet {

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
      String[] values = map.get("BenchmarkTest00506");
      if (values != null) param = values[0];
    }

    // Chain a bunch of propagators in sequence
    String a5528 = param; // assign
    StringBuilder b5528 = new StringBuilder(a5528); // stick in stringbuilder
    b5528.append(" SafeStuff"); // append some safe content
    b5528.replace(
        b5528.length() - "Chars".length(),
        b5528.length(),
        "Chars"); // replace some of the end content
    java.util.HashMap<String, Object> map5528 = new java.util.HashMap<String, Object>();
    map5528.put("key5528", b5528.toString()); // put in a collection
    String c5528 = (String) map5528.get("key5528"); // get it back out
    String d5528 = c5528.substring(0, c5528.length() - 1); // extract most of it
    String e5528 =
        new String(
            org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                    d5528.getBytes()))); // B64 encode and decode it
    String f5528 = e5528.split(" ")[0]; // split it on a space
    org.owasp.benchmark.helpers.ThingInterface thing =
        org.owasp.benchmark.helpers.ThingFactory.createThing();
    String g5528 = "barbarians_at_the_gate"; // This is static so this whole flow is 'safe'
    String bar = thing.doSomething(g5528); // reflection

    try {
      int r = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt();
      @RUntainted String rememberMeKey = Integer.toString(r);

      String user = "SafeIngrid";
      String fullClassName = this.getClass().getName();
      String testCaseNumber =
          fullClassName.substring(fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length());
      user += testCaseNumber;

      @RUntainted String cookieName = "rememberMe" + testCaseNumber;

      boolean foundUser = false;
      javax.servlet.http.Cookie[] cookies = request.getCookies();
      if (cookies != null) {
        for (int i = 0; !foundUser && i < cookies.length; i++) {
          javax.servlet.http.Cookie cookie = cookies[i];
          if (cookieName.equals(cookie.getName())) {
            if (cookie.getValue().equals(request.getSession().getAttribute(cookieName))) {
              foundUser = true;
            }
          }
        }
      }

      if (foundUser) {
        response.getWriter().println("Welcome back: " + user + "<br/>");
      } else {
        javax.servlet.http.Cookie rememberMe =
            new javax.servlet.http.Cookie(cookieName, rememberMeKey);
        rememberMe.setSecure(true);
        rememberMe.setHttpOnly(true);
        rememberMe.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
        // e.g., /benchmark/sql-01/BenchmarkTest01001
        request.getSession().setAttribute(cookieName, rememberMeKey);
        response.addCookie(rememberMe);
        response
            .getWriter()
            .println(
                user
                    + " has been remembered with cookie: "
                    + rememberMe.getName()
                    + " whose value is: "
                    + rememberMe.getValue()
                    + "<br/>");
      }
    } catch (java.security.NoSuchAlgorithmException e) {
      System.out.println("Problem executing SecureRandom.nextInt() - TestCase");
      throw new ServletException(e);
    }
    response
        .getWriter()
        .println("Weak Randomness Test java.security.SecureRandom.nextInt() executed");
  }
}
