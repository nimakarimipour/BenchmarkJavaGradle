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

@WebServlet(value = "/weakrand-00/BenchmarkTest00083")
public class BenchmarkTest00083 extends HttpServlet {

  private static final long serialVersionUID = 1L;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    javax.servlet.http.Cookie userCookie =
        new javax.servlet.http.Cookie("BenchmarkTest00083", "whatever");
    userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
    userCookie.setSecure(true);
    userCookie.setPath(request.getRequestURI());
    userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
    response.addCookie(userCookie);
    javax.servlet.RequestDispatcher rd =
        request.getRequestDispatcher("/weakrand-00/BenchmarkTest00083.html");
    rd.include(request, response);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");

    javax.servlet.http.Cookie[] theCookies = request.getCookies();

    String param = "noCookieValueSupplied";
    if (theCookies != null) {
      for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00083")) {
          param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
          break;
        }
      }
    }

    String bar;

    // Simple if statement that assigns param to bar on true condition
    int num = 196;
    if ((500 / 42) + num > 200) bar = param;
    else bar = "This should never happen";

    int randNumber = new java.util.Random().nextInt(99);
    String rememberMeKey = Integer.toString(randNumber);

    String user = "Inga";
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

    response.getWriter().println("Weak Randomness Test java.util.Random.nextInt(int) executed");
  }
}
