import random
import design


class hasardFunction():


    def randomDesign(self):
        listDesign = [1, 2, 3]
        choice = random.choice(listDesign)

        if choice == 1:
            design.Design.designMickey(None)
        elif choice == 2:
            design.Design.pinkPanther(None)

        elif choice == 3:
            design.Design.intrusionMan(None)
