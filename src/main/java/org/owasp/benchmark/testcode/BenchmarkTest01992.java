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

@WebServlet(value = "/weakrand-04/BenchmarkTest01992")
public class BenchmarkTest01992 extends HttpServlet {

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
    java.util.Enumeration<String> names = request.getHeaderNames();
    while (names.hasMoreElements()) {
      String name = (String) names.nextElement();

      if (org.owasp.benchmark.helpers.Utils.commonHeaders.contains(name)) {
        continue; // If standard header, move on to next one
      }

      java.util.Enumeration<String> values = request.getHeaders(name);
      if (values != null && values.hasMoreElements()) {
        param = name; // Grabs the name of the first non-standard header as the parameter
        // value
        break;
      }
    }
    // Note: We don't URL decode header names because people don't normally do that

    String bar = doSomething(request, param);

    double value = java.lang.Math.random();
    @RUntainted String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.

    String user = "Doug";
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
    response.getWriter().println("Weak Randomness Test java.lang.Math.random() executed");
  } // end doPost

  private static String doSomething(HttpServletRequest request, String param)
      throws ServletException, IOException {

    // Chain a bunch of propagators in sequence
    String a82010 = param; // assign
    StringBuilder b82010 = new StringBuilder(a82010); // stick in stringbuilder
    b82010.append(" SafeStuff"); // append some safe content
    b82010.replace(
        b82010.length() - "Chars".length(),
        b82010.length(),
        "Chars"); // replace some of the end content
    java.util.HashMap<String, Object> map82010 = new java.util.HashMap<String, Object>();
    map82010.put("key82010", b82010.toString()); // put in a collection
    String c82010 = (String) map82010.get("key82010"); // get it back out
    String d82010 = c82010.substring(0, c82010.length() - 1); // extract most of it
    String e82010 =
        new String(
            org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                    d82010.getBytes()))); // B64 encode and decode it
    String f82010 = e82010.split(" ")[0]; // split it on a space
    org.owasp.benchmark.helpers.ThingInterface thing =
        org.owasp.benchmark.helpers.ThingFactory.createThing();
    String bar = thing.doSomething(f82010); // reflection

    return bar;
  }
}
