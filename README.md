# Perky's-List
Final project for the BackEnd section in Udacity's Full Stack nanodegree.

## Setup:
- Install the Vagrant and Virtual Box
- Clone the GitHub repository [http://github.com/udacity/fullstack-nanodegree-vm](FullStack-VM)
- Run the virtual machine!
'''$cd vagrant
$vagrant up
$vagrant ssh
'''
-   change to the /vagrant directory by typing **cd /vagrant**.
- Install all required packages in the requirements.txt file
'''$pip install -r requirements.txt'''


## Running the Catalog App
- Run **python database_setup.py** to initialize the database.
- Run itemdump.py
- Run applicayion.py to run the Flask web server.
- In your browser visit **http://localhost:8000** to view the restaurant menu app.
  You should be able to view, add, edit, and delete menu items and restaurants.

# Catalogg App
Once the app is up and running you are able to view the main page, the item
description, category item list, and index item list without being logged in.
In order to add or edit items or categories, you need to login via google plus
by clicking on the login button. If attempting to edit something without being
authorized, you'll receive a flash messaged (displayed at the top of the screen)
If you're the owner, you can also delete items and categories.

You can add new categories and items via the navbar. To edit categories, you
have the option when you click on a category name and expand it to the item list.
For items, via the item description, also reached through clicking on an item.


## Project Details
