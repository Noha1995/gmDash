# GMail Account Management Project

App authentication/authorization, Add/Remove filters, update Vacations Setting, Delete the bulk messages through GMail API. 

    Python==3.6.8
    Django==2.2.7
    
    apiclient==1.0.4
    google-api-python-client==1.7.11
    google-auth==1.7.0
    google-auth-httplib2==0.0.3
    google-auth-oauthlib==0.4.1
    httplib2==0.14.0
    ...
    ...

## Main Functions

- __Authentication and authorization through GMail oAuth2 API.__

- __Filter Management__
    * Bulk add a filter on the registered GMail accounts.
    * Bulk delete filters on the registered GMail accounts.
    * Remove all filters on all of the registered GMail accounts
    
 - __Vacation Setting__
    * Bulk update the vacation setting on the registered GMail accounts.
    
- __Message Management__
    * Delete all messages on a GMail account.
    * Bulk Delete all messages on the registered GMail accounts.
    
- __User Management with permissions__
    * 4 groups supported. Staff(Django), ADMIN, USERA, USERB
    * Agent login: 
        * Users in ADMIN, USERA and Staff can login to ones' accounts in USERB group.
        
## Change History
- __2019-03-26__
    * Add Searchbox.
        * Page Vacation Multipe Setting
        * Page Add Filter
        * Page Set Sender Name
    * Change Comment Style
        ```
        """Description Text
        
        Args - Arguments Part
            arg1: argument description
            
        Returns - Returns Part
            arg1: return value description
        """
        ```
- __2019-11-25__
    * Prototype app for a cron job.
        * Use django_cron
        
          ``` 
            py manage.py runcrons --force 
          ```
        * Use crontab?
- __2019-11-24__
    * Permission management on dashboard
    * Fix a bug on deletion of the bulk messages.