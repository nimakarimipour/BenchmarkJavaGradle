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

@WebServlet(value = "/weakrand-01/BenchmarkTest00502")
public class BenchmarkTest00502 extends HttpServlet {

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
      String[] values = map.get("BenchmarkTest00502");
      if (values != null) param = values[0];
    }

    org.owasp.benchmark.helpers.ThingInterface thing =
        org.owasp.benchmark.helpers.ThingFactory.createThing();
    String bar = thing.doSomething(param);

    try {
      java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");

      // Get 40 random bytes
      byte[] randomBytes = new byte[40];
      getNextNumber(numGen, randomBytes);

      @RUntainted String rememberMeKey = org.owasp.esapi.ESAPI.encoder().encodeForBase64(randomBytes, true);

      String user = "SafeBystander";
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
      System.out.println("Problem executing SecureRandom.nextBytes() - TestCase");
      throw new ServletException(e);
    } finally {
      response
          .getWriter()
          .println("Randomness Test java.security.SecureRandom.nextBytes(byte[]) executed");
    }
  }

  void getNextNumber(java.util.Random generator, byte[] barray) {
    generator.nextBytes(barray);
  }
}
