<html>
<head>
<link rel="stylesheet" href="css/wro.css"/>
</head>
<body>
<#if RequestParameters['error']??>
	<div class="alert alert-danger">
		There was a problem logging in. Please try again.
	</div>
</#if>
	<div class="container">
		<form role="form" action="/secure/two_factor_authentication" method="post">
		  <div class="form-group">
		    <label for="pinCode">Pin Code:</label>
		    <input type="text" class="form-control" id="pinCode" name="pinCode"/>
		  </div>

		  <input type="hidden" id="csrf_token" name="${_csrf.parameterName}" value="${_csrf.token}"/>
		  <button type="submit" class="btn btn-primary">Submit</button>
		</form>
	</div>
	<script src="js/wro.js" type="text/javascript"></script>
</body>
</html>