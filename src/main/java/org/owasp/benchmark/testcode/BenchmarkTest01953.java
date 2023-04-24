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

@WebServlet(value = "/weakrand-04/BenchmarkTest01953")
public class BenchmarkTest01953 extends HttpServlet {

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
    if (request.getHeader("BenchmarkTest01953") != null) {
      param = request.getHeader("BenchmarkTest01953");
    }

    // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
    param = java.net.URLDecoder.decode(param, "UTF-8");

    String bar = doSomething(request, param);

    try {
      long l = java.security.SecureRandom.getInstance("SHA1PRNG").nextLong();
      String rememberMeKey = Long.toString(l);

      String user = "SafeLogan";
      String fullClassName = this.getClass().getName();
      String testCaseNumber =
          fullClassName.substring(fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length());
      user += testCaseNumber;

      String cookieName = "rememberMe" + testCaseNumber;

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
      System.out.println("Problem executing SecureRandom.nextLong() - TestCase");
      throw new ServletException(e);
    }
    response
        .getWriter()
        .println("Weak Randomness Test java.security.SecureRandom.nextLong() executed");
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    String bar;

    // Simple if statement that assigns constant to bar on true condition
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;

    return bar;
  }
}
