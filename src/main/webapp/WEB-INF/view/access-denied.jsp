<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ page isELIgnored="false"%>
<%@ taglib prefix="security"
	uri="http://www.springframework.org/security/tags"%>
<!doctype html>
<html lang="en">

<head>

<title>Selma Access denied page</title>
</head>

<body>

<h2>Access denied - You are not authorized to access this resources</h2>
<hr>

<a href="${pageContext.request.contextPath}/"> Back to home page </a>
</body>
</html>