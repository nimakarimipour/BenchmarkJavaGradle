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

@WebServlet(value = "/weakrand-04/BenchmarkTest01854")
public class BenchmarkTest01854 extends HttpServlet {

  private static final long serialVersionUID = 1L;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    javax.servlet.http.Cookie userCookie =
        new javax.servlet.http.Cookie("BenchmarkTest01854", "whatever");
    userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
    userCookie.setSecure(true);
    userCookie.setPath(request.getRequestURI());
    userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
    response.addCookie(userCookie);
    javax.servlet.RequestDispatcher rd =
        request.getRequestDispatcher("/weakrand-04/BenchmarkTest01854.html");
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
        if (theCookie.getName().equals("BenchmarkTest01854")) {
          param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
          break;
        }
      }
    }

    String bar = doSomething(request, param);

    float rand = new java.util.Random().nextFloat();
    String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.

    String user = "Floyd";
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
      rememberMe.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
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

    response.getWriter().println("Weak Randomness Test java.util.Random.nextFloat() executed");
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    // Chain a bunch of propagators in sequence
    String a34242 = param; // assign
    StringBuilder b34242 = new StringBuilder(a34242); // stick in stringbuilder
    b34242.append(" SafeStuff"); // append some safe content
    b34242.replace(
        b34242.length() - "Chars".length(),
        b34242.length(),
        "Chars"); // replace some of the end content
    java.util.HashMap<String, Object> map34242 = new java.util.HashMap<String, Object>();
    map34242.put("key34242", b34242.toString()); // put in a collection
    String c34242 = (String) map34242.get("key34242"); // get it back out
    String d34242 = c34242.substring(0, c34242.length() - 1); // extract most of it
    String e34242 =
        new String(
            org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                    d34242.getBytes()))); // B64 encode and decode it
    String f34242 = e34242.split(" ")[0]; // split it on a space
    org.owasp.benchmark.helpers.ThingInterface thing =
        org.owasp.benchmark.helpers.ThingFactory.createThing();
    String g34242 = "barbarians_at_the_gate"; // This is static so this whole flow is 'safe'
    String bar = thing.doSomething(g34242); // reflection

    return bar;
  }
}
