# aws-ad

This project provides command line tool - aws-ad to simplify process of logging into AWS account with Windows AD credentials

It is inspired by basically identical tool aws-adfs. I wrote it mainly out of curioucity how to do it by myself, and was to lazy to check, why orginal tool 
randomly refused to work under bamboo


# Sample workflow

1. Create config file: `~/.aws/auth`. It will be used by `aws-ad` to connect to ADFS site and to login. Here is sample content:


        [profile-name]
            username=login@your-domain.com
            # password=your-password - this is OPTIONAL
            adfs-host=sts.your-domain.com
            provider-id=urn:amazon:your-company-provider-id
            role-arn=arn:aws:iam::1234567890:role/ADFS_ROLE_FOR_TASK
            
            # session duration can be increased to 24 hours (720 minutes)
            session-duration-minutes=60
            
            # OPTIONAL variables that change behaviour of profile :
            # assume-role=arn:aws:iam::1234567890:role/role-to-assume-into-after-gettin-in
            # assume-profile=name-of-the-new-profile

    
2. Run `aws-ad` with following options:


        aws-ad --profile profile-name

    
Keep in mind that `profile-name` must be the same as in config file above
You may be prompted for password (to your login@your-domain.com in Active Directory).
`aws-ad` modifies file `~/.aws/credentials`. It saves AWS keys there in profile section (`profile-name` again).

3. You can now run AWS CLI commands now. Remember to set AWS Region and AWS Profile, like this:


        export AWS_DEFAULT_PROFILE=profile-name
        export AWS_DEFAULT_REGION=eu-central-1
        aws s3 ls


