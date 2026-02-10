import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report

x,y = make_classification(
    n_samples=3000,
    n_features=40,  #pretend PE features
    n_informative=20,
    n_redundant=10,
    n_classes=2,
    weights=[0.7, 0.3],  #imbalanced like real malware data
    random_state=42
)
np.savetxt('malware_dataset.csv',x, delimiter=',')
np.savetxt('malware_labels.csv',y, delimiter=',')

x = np.loadtxt('malware_dataset.csv', delimiter=',')
y = np.loadtxt('malware_labels.csv', delimiter=',')

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

#max_depth = prevents overfitting by limiting tree complexity
#random_state = ensures same result every run 
clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(x_train, y_train)

y_pred = clf.predict(x_test)

# internally y_pred used here
print("Accuracy:", clf.score(x_test, y_test))

print("Report:", classification_report(y_test, y_pred))