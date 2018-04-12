# Perky's-List
This is an item catalog where goods can be offered. No transactions can be made, but offers and contact can be made.
It is the project for the **BackEnd** section in Udacity's Full Stack Nanodegree.


## Machine Setup:
- Install the Vagrant and Virtual Box
- Clone the GitHub repository [http://github.com/udacity/fullstack-nanodegree-vm](FullStack-VM)
- Change director to where you saved the fullstack directory
- Run the virtual machine and change into the vagrant directory!
`$cd vagrant`
`$vagrant up`
`$vagrant ssh`
`cd \vagrant`
- Change directory to the /vagrant directory by typing **cd /vagrant**.
- Install all required packages in the requirements.txt file
`$pip install -r requirements.txt`

## Running the Catalog App
- Run **python database_setup.py** to initialize the database.
- Run itemdump.py
- Run applicayion.py to run the Flask web server.
- In your browser visit **http://localhost:8000** to view the catalog main page.


## Catalogg App
Once the app is up and running you are able to view the main page, the item
description, category item list, and index item list without being logged in.
In order to add or edit items or categories, you need to login via google plus
by clicking on the login button. If attempting to edit something without being
authorized, you'll receive a flash messaged (displayed at the top of the screen)
If you're the owner, you can also delete items and categories.

From the main page, you can access everything.
- Use navbar to add new categories and items.
- Clicking on a category gives you the category item list and category edit options.
- Clicking on an item gives you the item description and item editing page.

### Authorization
Authorization is only required to edit categories and items, being only the creator of them can actually edit them. 
In case of a category, this is more complicated, and only the administrator should have the right to change it. But in this case, only the owner can change it, which should affect only the single item and not all items under the same category.

### References
- The bulk of this project was constructed using materials/solutions from the Udacity restaurant-menu projects developed along the course.
- In addition, the Flask manual and particularly the [Flask Mega Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world) were great to resolve problems and check functions.
- The Udacity forum and search functionality is great, with lots of "problems" are shared among several users and guidance in solving them is provided.
- Stack Overflow of course has an answer for just about every bug or problem!
- W3C has some great CSS/HTML help and funtionality, as well as bootstrapping possibilities.
