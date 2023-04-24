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

@WebServlet(value = "/weakrand-02/BenchmarkTest01136")
public class BenchmarkTest01136 extends HttpServlet {

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

    String bar = new Test().doSomething(request, param);

    try {
      java.security.SecureRandom secureRandomGenerator =
          java.security.SecureRandom.getInstance("SHA1PRNG");

      // Get 40 random bytes
      byte[] randomBytes = new byte[40];
      secureRandomGenerator.nextBytes(randomBytes);

      String rememberMeKey = org.owasp.esapi.ESAPI.encoder().encodeForBase64(randomBytes, true);

      String user = "SafeByron";
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
      System.out.println("Problem executing SecureRandom.nextBytes() - TestCase");
      throw new ServletException(e);
    } finally {
      response
          .getWriter()
          .println("Randomness Test java.security.SecureRandom.nextBytes(byte[]) executed");
    }
  } // end doPost

  private class Test {

    public String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {

      // Chain a bunch of propagators in sequence
      String a58606 = param; // assign
      StringBuilder b58606 = new StringBuilder(a58606); // stick in stringbuilder
      b58606.append(" SafeStuff"); // append some safe content
      b58606.replace(
          b58606.length() - "Chars".length(),
          b58606.length(),
          "Chars"); // replace some of the end content
      java.util.HashMap<String, Object> map58606 = new java.util.HashMap<String, Object>();
      map58606.put("key58606", b58606.toString()); // put in a collection
      String c58606 = (String) map58606.get("key58606"); // get it back out
      String d58606 = c58606.substring(0, c58606.length() - 1); // extract most of it
      String e58606 =
          new String(
              org.apache.commons.codec.binary.Base64.decodeBase64(
                  org.apache.commons.codec.binary.Base64.encodeBase64(
                      d58606.getBytes()))); // B64 encode and decode it
      String f58606 = e58606.split(" ")[0]; // split it on a space
      org.owasp.benchmark.helpers.ThingInterface thing =
          org.owasp.benchmark.helpers.ThingFactory.createThing();
      String g58606 = "barbarians_at_the_gate"; // This is static so this whole flow is 'safe'
      String bar = thing.doSomething(g58606); // reflection

      return bar;
    }
  } // end innerclass Test
} // end DataflowThruInnerClass
