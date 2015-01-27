<html>
	<head></head>
	<body>
		<div>
			<h1><%=currentNode.title%></h1>
			<h3>Username : <%=request.getRemoteUser()%></h3>
		</div>
		<div>
			<form action="/sling/sad_check" method="POST">
				<input type="text" name="j_username" value="msadow"/>
				<input type="text" name="j_password" value="password"/>
				<input type="submit" value="Submit!" />
			</form>
		</div>
	</body>
</html>