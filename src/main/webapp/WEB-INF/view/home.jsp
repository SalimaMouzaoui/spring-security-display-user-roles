<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="security"
	uri="http://www.springframework.org/security/tags"%>
<%@ page isELIgnored="false"%>
<html>

<head>
<title>Selma Company Home Page</title>
</head>

<body>
	<h2>Selma Company Home Page</h2>
	<hr>

	<p>
		User :
		<security:authentication property="principal.username" />
	</p>
	<p>
		Roles :
		<security:authentication property="principal.authorities" />
	</p>

	<hr>
	
	<!-- add a point to /leaders for managers -->
	<security:authorize access="hasRole('MANAGER')">
		<p>
			<a href="${pageContext.request.contextPath}/leaders">LeaderShip
				Meeting</a> (Only for Manager peeps)
		</p>
	</security:authorize>
	
	<!-- add a point to /systems for admins -->
	<security:authorize access="hasRole('ADMIN')">
		<p>
			<a href="${pageContext.request.contextPath}/systems">IT System
				Meeting</a> (Only for Admin peeps)
		</p>
	</security:authorize>

	<p>Welcome to the Selma company home page!</p>

	<!-- Add a logout button -->
	<form:form action="${pageContext.request.contextPath}/logout"
		method="POST">

		<input type="submit" value="Logout" />

	</form:form>

</body>

</html>