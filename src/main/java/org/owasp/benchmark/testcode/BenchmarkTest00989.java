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

import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/weakrand-02/BenchmarkTest00989")
public class BenchmarkTest00989 extends HttpServlet {

  private static final long serialVersionUID = 1L;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    javax.servlet.http.Cookie userCookie =
        new javax.servlet.http.Cookie("BenchmarkTest00989", "whatever");
    userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
    userCookie.setSecure(true);
    userCookie.setPath(request.getRequestURI());
    userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
    response.addCookie(userCookie);
    javax.servlet.RequestDispatcher rd =
        request.getRequestDispatcher("/weakrand-02/BenchmarkTest00989.html");
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
        if (theCookie.getName().equals("BenchmarkTest00989")) {
          param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
          break;
        }
      }
    }

    String bar = new Test().doSomething(request, param);

    try {
      int randNumber = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);
      @RUntainted String rememberMeKey = Integer.toString(randNumber);

      String user = "SafeInga";
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
      System.out.println("Problem executing SecureRandom.nextInt(int) - TestCase");
      throw new ServletException(e);
    }
    response
        .getWriter()
        .println("Weak Randomness Test java.security.SecureRandom.nextInt(int) executed");
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      // Chain a bunch of propagators in sequence
      String a36538 = param; // assign
      StringBuilder b36538 = new StringBuilder(a36538); // stick in stringbuilder
      b36538.append(" SafeStuff"); // append some safe content
      b36538.replace(
          b36538.length() - "Chars".length(),
          b36538.length(),
          "Chars"); // replace some of the end content
      java.util.HashMap<String, Object> map36538 = new java.util.HashMap<String, Object>();
      map36538.put("key36538", b36538.toString()); // put in a collection
      String c36538 = (String) map36538.get("key36538"); // get it back out
      String d36538 = c36538.substring(0, c36538.length() - 1); // extract most of it
      String e36538 =
          new String(
              org.apache.commons.codec.binary.Base64.decodeBase64(
                  org.apache.commons.codec.binary.Base64.encodeBase64(
                      d36538.getBytes()))); // B64 encode and decode it
      String f36538 = e36538.split(" ")[0]; // split it on a space
      org.owasp.benchmark.helpers.ThingInterface thing =
          org.owasp.benchmark.helpers.ThingFactory.createThing();
      String bar = thing.doSomething(f36538); // reflection

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
