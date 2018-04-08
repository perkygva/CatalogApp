from flask import Flask, render_template, request, redirect, jsonify, url_for, make_response, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Items, User
from flask import session as login_session
from flask_login import login_required, logout_user
import os, random, string, json, httplib2, requests
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from functools import wraps

# Flask Instance
app = Flask(__name__)

# GConnect
CLIENT_ID = json.loads(open("client_secrets.json", "r").read())['web']['client_id']
CLIENT_SECRET = json.loads(open("client_secrets.json", "r").read())['web']['client_secret']
APPLICATION_NAME = "CatalogApp"

# Connect to the database catalog.db
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Setup Login/logout routing standard, gg
@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Google plus connect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    print "access token received %s" % code

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session["picture"] = data["picture"]
    login_session['email'] = data['email']
    login_session["provider"] = "google"

    user_id = getUserID(login_session["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session["user_id"] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output



## Facebook login Removed due to issues with HTTPS security requirements.
# @app.route('/fbconnect', methods=['POST'])
# def fbconnect():
#     if request.args.get('state') != login_session['state']:
#         response = make_response(json.dumps('Invalid state parameter.'), 401)
#         response.headers['Content-Type'] = 'application/json'
#         return response
#     access_token = request.data
#     print "access token received %s " % access_token
#
#
#     app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
#         'web']['app_id']
#     app_secret = json.loads(
#         open('fb_client_secrets.json', 'r').read())['web']['app_secret']
#     url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
#         app_id, app_secret, access_token)
#     h = httplib2.Http()
#     result = h.request(url, 'GET')[1]
#     print(result)
#
#     # Use token to get user info from API
#     userinfo_url = "https://graph.facebook.com/v2.12/me"
#     '''
#         Due to the formatting for the result from the server token exchange we have to
#         split the token first on commas and select the first index which gives us the key : value
#         for the server access token then we split it on colons to pull out the actual token value
#         and replace the remaining quotes with nothing so that it can be used directly in the graph
#         api calls
#     '''
#     token = result.split(',')[0].split(':')[1].replace('"', '')
#
#     url = 'https://graph.facebook.com/v2.12/me?access_token=%s&fields=name,id,email' % token
#     h = httplib2.Http()
#     result = h.request(url, 'GET')[1]
#     # print "url sent for API access:%s"% url
#     # print "API JSON result: %s" % result
#     data = json.loads(result)
#     login_session['provider'] = 'facebook'
#     login_session['username'] = data["name"]
#     login_session['email'] = data["email"]
#     login_session['facebook_id'] = data["id"]
#
#     # The token must be stored in the login_session in order to properly logout
#     login_session['access_token'] = token
#
#     # Get user picture
#     url = 'https://graph.facebook.com/v2.12/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
#     h = httplib2.Http()
#     result = h.request(url, 'GET')[1]
#     data = json.loads(result)
#
#     login_session['picture'] = data["data"]["url"]
#
#     # see if user exists
#     user_id = getUserID(login_session['email'])
#     if not user_id:
#         user_id = createUser(login_session)
#     login_session['user_id'] = user_id
#
#     output = ''
#     output += '<h1>Welcome, '
#     output += login_session['username']
#
#     output += '!</h1>'
#     output += '<img src="'
#     output += login_session['picture']
#     output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
#
#     flash("Now logged in as %s" % login_session['username'])
#     return output
#
#
# @app.route('/fbdisconnect')
# def fbdisconnect():
#     facebook_id = login_session['facebook_id']
#     # The access token must me included to successfully logout
#     access_token = login_session['access_token']
#     url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
#     h = httplib2.Http()
#     result = h.request(url, 'DELETE')[1]
#     return "you have been logged out"

###########
# Use helper functions from course materials
def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

#####################
# JSON APIs endpoints
@app.route('/catalog/JSON')
def catalogJSON():
    category = session.query(Category).all()
    items = session.query(Items).all()
    return jsonify(
        category = [c.serialize for c in category],
        items = [i.serialize for i in items])


# Flask set and routing
# Homepage - Show all category
@app.route('/')
@app.route('/catalog')
def showCatalog():
    """Main view of catalog, available to public - does not require login
    Order category alphabetically and items by date added."""
    category = session.query(Category).order_by(asc(Category.name))
    items = session.query(Items).order_by(Items.date.desc()).limit(10)
    return render_template('catalog.html', category = category, items = items)

# Show all items
@app.route('/<int:category_id>/items')
def showItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Items).filter_by(category_id = category_id).all()
    return render_template('items.html', items = items, category = category)

@app.route('/index')
def showIndex():
    category = session.query(Category).all()
    items = session.query(Items).all()
    return render_template('index.html', items = items, category = category)

# Item details, specification pagename
@app.route('/<int:category_id>/<int:item_id>')
def itemDescription(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Items).filter_by(id=item_id).one()
    return render_template("itemDescription.html", item = item, category = category)

#############
# EDITING
#############

# Add a new Category to catalog
@app.route('/catalog/newCategory', methods=['GET', 'POST'])
def newCategory():
    """Adding a category only requires the user to be logged in"""
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCategory = Category(
                                name=request.form['name'],
                                user_id = login_session["user_id"])
        session.add(newCategory)
        session.commit()
        flash("New category {} added " .format(newCategory.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')
        flash("Error creating new category, try again")


# Edit a category
@app.route('/catalog/<int:category_id>/categoryEdit', methods=['GET', 'POST'])
def editCategory(category_id):
    """In addiion to being logged in must be the owner of the category"""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session["user_id"]:
        return flash("You are not the owner of this category and cannot edit it")
    # POST methods
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
        session.add(category)
        session.commit()
        flash('Category Item Successfully Edited!')
        return  redirect(url_for('showCatalog'))
    else:
        return render_template('editCategory.html', category=category)


@app.route('/catalog/<int:category_id>/deleteCategory', methods=['GET', 'POST'])
def deleteCategory(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    # See if the logged in user is the owner of item
    # If logged in user != item owner redirect them
    if category.user_id != login_session['user_id']:
        flash ("You cannot delete this category as it belongs to someone else.")
        return redirect(url_for('showCatalog'))
    if request.method =='POST':
        session.delete(category)
        session.commit()
        flash('Category {} Successfully Deleted! ' .format(category.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html', category=category)

# EDITING ITEMS SECTION - must be logged in for all
@app.route('/catalog/newItems', methods=['GET', 'POST'])
#@login_required
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).all()
    if request.method == 'POST':
        newItem = Items(
        name=request.form['name'],
        description=request.form['description'],
        price = request.form['price'],
        category_id = request.form["category"],
        user_id=login_session["user_id"])

        session.add(newItem)
        session.commit()
        flash('Item {} Successfully Added!' .format(newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('addItem.html', category=category)
        flash("Item not added, please try again")
# Edit an item
@app.route('/catalog/<int:item_id>/editItem', methods=['GET', 'POST'])
def editItem(item_id):
    #if 'username' not in login_session:
    #    return redirect('/login')
    categories = session.query(Category).all()
    items = session.query(Items).all()
    editedItem = session.query(Items).filter_by(id=item_id).one()
    user = login_session["user_id"]     # See if the logged in user is the owner of item

    # POST methods
    if request.method == 'POST':
        if user != editedItem.user_id:
            flash ("You cannot edit this item. You can only edit your items!")
            return redirect(url_for('login'))
        if request.form['name']:
            category = session.query(Category).filter_by(id=request.form['category']).one()
            editedItem.name = request.form['name']
            editedItem.description = request.form['description']
            editedItem.price = request.form['price']
            editedItem.category_id = category.id

        #session.add(editedItem)
        #session.commit()
        flash("Successfully updated item {}" .format(editedItem.name))
        return redirect(url_for("showItems", category_id = editedItem.category_id))
    else:
        return render_template('editItem.html', item=editedItem, items=items, categories=categories)

# Delete an item, category deletion is excluded as this would delete all items within. Only admin should have category deletion rights
@app.route('/catalog/<int:item_id>/deleteItem', methods=['GET', 'POST'])
def deleteItem(item_id):
    item = session.query(Items).filter_by(id=item_id).one()
    # See if the logged in user is the owner of item
    # If logged in user != item owner redirect them
    if item.user_id != login_session['user_id']:
        flash ("You cannot delete this item as it belongs to someone else.")
        return redirect(url_for('showCatalog'))
    if request.method =='POST':
        session.delete(item)
        session.commit()
        flash('Item {} Successfully Deleted! ' .format(item.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteItem.html', item=item)

@app.route('/contact')
def contact():
    return render_template("contactForm.html")

# Disconnect and reset login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if results['status'] == '200':
        #Reset user accounts
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider
@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']

        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))
if __name__ == '__main__':
    app.debug = True
    app.secret_key = "secret_key"
    app.run(host='0.0.0.0', port=8000)
