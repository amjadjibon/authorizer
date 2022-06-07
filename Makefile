VERSION = "0.0.1"
change-version-basicauth:
	@echo $(VERSION)>basicauth/VERSION
	@echo "package constant\n\n// Version constant of the authorizer\nconst Version = \"$(VERSION)\"">basicauth/constant/version.go
	@git add basicauth/VERSION
	@git add basicauth/constant/version.go
	@git commit -m "basicauth/v$(VERSION)"
	@git tag -a "basicauth/v$(VERSION)" -m "basicauth/v$(VERSION)"
	@git push origin master
	@git push origin "basicauth/v$(VERSION)"
