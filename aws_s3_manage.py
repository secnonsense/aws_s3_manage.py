import tkinter as tk
from tkinter import ttk, messagebox
import boto3
import configparser
import os
import json
import time

class AWSCredentialManager:
    def __init__(self, master):
        self.master = master
        master.title("AWS User and Credentials Manager")

        self.config = configparser.ConfigParser()
        self.credentials_file = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')
        self.config.read(self.credentials_file)
        self.profiles = self.config.sections()

        if "default" not in self.profiles:
            self.profiles.insert(0, "default")

        # Labels
        ttk.Label(master, text="AWS Profile:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(master, text="S3 Bucket Name:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(master, text="S3 Prefix (Folder):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(master, text="New Username:").grid(row=3, column=0, padx=5, pady=5, sticky="w")

        # Entry Widgets and Dropdown
        self.profile_var = tk.StringVar(master)
        self.profile_var.set("default")
        self.profile_dropdown = ttk.Combobox(master, textvariable=self.profile_var, values=self.profiles, state="readonly")
        self.profile_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.bucket_entry = ttk.Entry(master)
        self.bucket_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.prefix_entry = ttk.Entry(master)
        self.prefix_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.username_entry = ttk.Entry(master)
        self.username_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        # Buttons
        create_button = ttk.Button(master, text="Create User & Add Credentials", command=self.create_user_prefix_handle_policy)
        create_button.grid(row=4, column=0, columnspan=2, pady=10)

        remove_user_button = ttk.Button(master, text="Remove User, Credentials, Policy", command=self.remove_user_and_credentials)
        remove_user_button.grid(row=5, column=0, columnspan=2, pady=10)

        remove_prefix_button = ttk.Button(master, text="Remove S3 Prefix", command=self.remove_s3_prefix)
        remove_prefix_button.grid(row=6, column=0, columnspan=2, pady=10)

        master.grid_columnconfigure(1, weight=1)

    def get_aws_session(self, profile_name="default"):
        if profile_name == "default":
            return boto3.Session()
        else:
            return boto3.Session(profile_name=profile_name)
        
    def update_profile_dropdown(self):
        self.config.read(self.credentials_file)
        self.profiles = self.config.sections()
        if "default" not in self.profiles and self.config.has_section("default"):
            self.profiles.insert(0, "default")
        self.profile_dropdown['values'] = self.profiles
        if self.profiles:
            self.profile_var.set(self.profiles[0])
        else:
            self.profile_var.set("default")

    def create_user_prefix_handle_policy(self):
        bucket_name = self.bucket_entry.get()
        prefix = self.prefix_entry.get()
        username = self.username_entry.get()
        profile_name = self.profile_var.get()

        if not all([bucket_name, prefix, username]):
            messagebox.showerror("Error", "Please fill in all the fields.")
            return

        new_profile_name = username

        session = self.get_aws_session(profile_name)
        iam_client = session.client('iam')
        s3_client = session.client('s3')

        try:
            # Create the IAM user
            iam_client.create_user(UserName=username)
            print(f"IAM user '{username}' created successfully.")

            # Create access keys for the user
            response = iam_client.create_access_key(UserName=username)
            access_key = response['AccessKey']['AccessKeyId']
            secret_key = response['AccessKey']['SecretAccessKey']
            print(f"Access keys generated for user '{username}'.")

            # Add credentials to ~/.aws/credentials
            self.config[new_profile_name] = {
                'aws_access_key_id': access_key,
                'aws_secret_access_key': secret_key
            }
            with open(self.credentials_file, 'w') as configfile:
                self.config.write(configfile)
            print(f"Credentials added to '{self.credentials_file}' under section '[{new_profile_name}]'.")

            # Create the S3 prefix (by uploading an empty object)
            try:
                s3_client.put_object(Bucket=bucket_name, Key=f"{prefix}/")
                print(f"S3 prefix '{prefix}/' created in bucket '{bucket_name}'.")
            except Exception as e:
                messagebox.showerror("Warning", f"Could not create S3 prefix: {e}")
                print(f"Warning: Could not create S3 prefix: {e}")

            # Get the ARN of the newly created user
            user_response = iam_client.get_user(UserName=username)
            user_arn = user_response['User']['Arn']
            print(f"Retrieved User ARN: {user_arn}")

            print("Waiting for a longer delay (10 seconds) for IAM user ARN to propagate...")
            time.sleep(10)

            # Define the new policy statements for the user and prefix
            new_statements = [
                {   "Sid": f"AllowPrefixAccess-{int(time.time())}",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"{user_arn}"
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket",
                        "s3:DeleteObject"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}/{prefix}*",
                        f"arn:aws:s3:::{bucket_name}"
                    ]
                },
                {
                    "Sid": f"DenyAllOther-{int(time.time())}",
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": f"{user_arn}"
                    },
                    "NotAction": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket",
                        "s3:DeleteObject"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}/{prefix}*",
                        f"arn:aws:s3:::{bucket_name}"
                    ]
                },
                {
                    "Sid": f"DenyRootAccess-{int(time.time())}",
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": f"{user_arn}"
                    },
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                    "Condition": {
                        "StringNotLike": {
                            "s3:Prefix": f"{prefix}*"
                        }
                    }
                }
            ]
            try:
                # Get the existing bucket policy
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                existing_policy = json.loads(policy_response['Policy'])
                if 'Statement' in existing_policy:
                    existing_statements = existing_policy['Statement']
                else:
                    existing_statements = []  # Initialize as empty if 'Statement' key is missing
                print(f"Successfully retrieved existing policy statements.")
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    print(f"No existing bucket policy found.")
                    existing_statements = []  # Ensure it's empty in this case too
                elif e.response['Error']['Code'] == 'MalformedPolicy':
                    print(f"Warning: Existing bucket policy is malformed and cannot be parsed. Proceeding with new policy only.")
                    print(f"Detailed MalformedPolicy Error: {e}")  # Print the full exception
                    existing_statements = []  # Treat as no valid existing statements
                else:
                    print(f"Error retrieving existing policy: {e}")
                    raise

            combined_statements = existing_statements + new_statements
            new_policy = {
                "Version": "2012-10-17",
                "Statement": combined_statements
            }
            policy_json = json.dumps(new_policy)

            print(f"Policy:\n{policy_json}\nBucket Name:{bucket_name}")

            # Apply the new policy
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy_json)
            print(f"S3 bucket policy applied to '{bucket_name}' for user '{username}' with prefix '{prefix}'.")

            messagebox.showinfo("Success", f"User '{username}' created, S3 prefix '{prefix}/' created, credentials added, and S3 policy applied.")

        except iam_client.exceptions.EntityAlreadyExistsException:
            messagebox.showerror("Error", f"IAM user '{username}' already exists.")
        except iam_client.exceptions.NoSuchEntityException:
            messagebox.showerror("Error", f"Could not find IAM user '{username}'.")
        except s3_client.exceptions.NoSuchBucket:
            messagebox.showerror("Error", f"S3 bucket '{bucket_name}' does not exist.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def remove_user_and_credentials(self):
        username_to_remove = self.username_entry.get() 
        selected_profile = self.profile_var.get()       
        bucket_name_for_policy = self.bucket_entry.get() 

        if not username_to_remove:
            messagebox.showerror("Error", "Please enter the username to remove.")
            return
        
        profile_to_remove = username_to_remove

        # Prompt for confirmation before removing user and credentials
        confirm_remove = messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove user '{username_to_remove}', their credentials, and their S3 bucket policy statements?", icon='warning')
        if not confirm_remove:
            return

        session = self.get_aws_session(selected_profile)
        iam_client = session.client('iam')
        s3_client = session.client('s3')

        try:
            # --- 1. Remove S3 User Policy Statements ---
            try:
                user_response = iam_client.get_user(UserName=username_to_remove)
                user_arn_to_remove = user_response['User']['Arn']
                print(f"Retrieved User ARN to remove from policy: {user_arn_to_remove}")

                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name_for_policy)
                    existing_policy = json.loads(policy_response['Policy'])
                    updated_statements = []
                    if 'Statement' in existing_policy:
                        for statement in existing_policy['Statement']:
                            if not (statement.get('Principal', {}).get('AWS') == user_arn_to_remove or
                                    (isinstance(statement.get('Principal', {}).get('AWS'), list) and user_arn_to_remove in statement.get('Principal', {}).get('AWS')) or
                                    statement.get('Sid', '').startswith('AllowPrefixAccess-') or
                                    statement.get('Sid', '').startswith('DenyAllOther-') or
                                    statement.get('Sid', '').startswith('DenyRootAccess-')):
                                updated_statements.append(statement)

                    if updated_statements:
                        updated_policy = {
                            "Version": "2012-10-17",
                            "Statement": updated_statements
                        }
                        updated_policy_json = json.dumps(updated_policy)
                        s3_client.put_bucket_policy(Bucket=bucket_name_for_policy, Policy=updated_policy_json)
                        print(f"S3 bucket policy updated for '{bucket_name_for_policy}' to remove statements for user '{username_to_remove}'.")
                    elif existing_policy.get('Statement'):
                        s3_client.delete_bucket_policy(Bucket=bucket_name_for_policy)
                        print(f"S3 bucket policy deleted for '{bucket_name_for_policy}' as no relevant statements remained.")

                except s3_client.exceptions.NoSuchBucketPolicy:
                    print(f"No bucket policy found for '{bucket_name_for_policy}'.")

            except iam_client.exceptions.NoSuchEntityException:
                print(f"IAM user '{username_to_remove}' not found. Cannot remove policy.")

            # --- 2. Remove access keys ---
            access_keys_response = iam_client.list_access_keys(UserName=username_to_remove)
            for access_key_info in access_keys_response['AccessKeyMetadata']:
                access_key_id = access_key_info['AccessKeyId']
                iam_client.delete_access_key(UserName=username_to_remove, AccessKeyId=access_key_id)
                print(f"Access key '{access_key_id}' deleted for user '{username_to_remove}'.")

            # --- 3. Remove the IAM user ---
            iam_client.delete_user(UserName=username_to_remove)
            print(f"IAM user '{username_to_remove}' deleted successfully.")
            messagebox.showinfo("Success", f"IAM user '{username_to_remove}', their access keys, and S3 policy statements have been removed.")

        except iam_client.exceptions.NoSuchEntityException:
            messagebox.showerror("Error", f"IAM user '{username_to_remove}' not found.")
            return
        except s3_client.exceptions.NoSuchBucket:
            messagebox.showerror("Error", f"S3 bucket '{bucket_name_for_policy}' not found.")
            return
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during the removal process: {e}")
            return

        # --- 4. Remove profile from ~/.aws/credentials ---
        config = configparser.ConfigParser()
        config.read(self.credentials_file)
        if config.has_section(profile_to_remove):
            config.remove_section(profile_to_remove)
            with open(self.credentials_file, 'w') as configfile:
                config.write(configfile)
            print(f"Profile '[{profile_to_remove}]' removed from '{self.credentials_file}'.")
            self.update_profile_dropdown()
            messagebox.showinfo("Success", f"Profile '[{profile_to_remove}]' removed from credentials file.")
        else:
            messagebox.showinfo("Info", f"Profile '[{profile_to_remove}]' not found in '{self.credentials_file}'.")


    def remove_s3_prefix(self):
        bucket_name_to_remove_prefix = self.bucket_entry.get()
        prefix_to_remove = self.prefix_entry.get() 
        selected_profile = self.profile_var.get()

        if not bucket_name_to_remove_prefix or not prefix_to_remove:
            messagebox.showerror("Error", "Please enter both the bucket name and the prefix to remove.")
            return

        session = self.get_aws_session(selected_profile)  # Use default profile
        s3_client = session.client('s3')

        try:
            # 1. List all objects with the prefix
            objects_to_delete = []
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket_name_to_remove_prefix, Prefix=prefix_to_remove)
            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        objects_to_delete.append({'Key': obj['Key']})

            # 2. Delete the objects (in batches of up to 1000)
            if objects_to_delete:
                for i in range(0, len(objects_to_delete), 1000):
                    response = s3_client.delete_objects(
                        Bucket=bucket_name_to_remove_prefix,
                        Delete={'Objects': objects_to_delete[i:i + 1000]}
                    )
                    if 'Errors' in response:
                        for error in response['Errors']:
                            print(f"Error deleting object '{error['Key']}': {error['Message']}")
                print(f"Successfully deleted {len(objects_to_delete)} objects with prefix '{prefix_to_remove}' from bucket '{bucket_name_to_remove_prefix}'.")
                messagebox.showinfo("Success", f"Successfully deleted objects with prefix '{prefix_to_remove}'.")
            else:
                messagebox.showinfo("Info", f"No objects found with prefix '{prefix_to_remove}' in bucket '{bucket_name_to_remove_prefix}'.")

            # 3. Optionally delete the prefix "folder" object (if it exists)
            prefix_object_key = prefix_to_remove
            try:
                s3_client.delete_object(Bucket=bucket_name_to_remove_prefix, Key=prefix_object_key)
                print(f"Optional prefix object '{prefix_object_key}' deleted.")
            except s3_client.exceptions.NoSuchKey:
                print(f"Optional prefix object '{prefix_object_key}' not found.")

        except s3_client.exceptions.NoSuchBucket:
            messagebox.showerror("Error", f"S3 bucket '{bucket_name_to_remove_prefix}' not found.")
            return
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while removing the prefix: {e}")
            return
   
if __name__ == "__main__":
    root = tk.Tk()
    app = AWSCredentialManager(root)
    root.mainloop()
