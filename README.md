# mynetdev

settings.yaml

	global:
	  token: NetboxToken
	  username: DeviceUserName
	  password: DeviceUserPassword
	  site: site_slug
	  domain: netbox_addres_or_fqdn
	HP:
	  - models: [ 1920-24g, 1920-24g-poe ]
	    password: Jinhua1920unauthorized
	  - models: [ v1910-24g-poe, 1920s-24g-2sfp, 3com-baseline-switch-2928-sfp ]
	    password: '512900'


By default in the command line you have only few commands. But if you enter hidden command "_cmdline-mode on" then you are prompted to confirm this command: "All commands can be displayed and executed. Continue? [Y/N]" – need to press "y" followed by a request to enter the factory password. The password depends on your device model.
