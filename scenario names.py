from scenebin import *
import os

shineStageTable = [0, 1, 2, 3, 4, 5, 6, 6, 7, 8, 9, 1, 1, 5, 6, 1, 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 3, 8, 4, 4, 5, 5, 5, 5, 5, 5, 6, 5, 7,
7, 8, 8, 2, 2, 3, 3, 5, 6, 9, 1, 1, 2, 6, 8, 5, 3, 9]
shineConvTable = [[86], [], [0, 1, 2, 3, 4, 5, 6, 7], [10, 11, 12, 13, 14, 15, 16, 17], [20, 21, 22, 23, 24, 25, 26, 27], [30, 31, 32, 33, 34, 35, 36, 37], [40, 41, 42, 43, 44, 45, 46, 47], [60, 65, 62, 61, 64, 63, 66, 67], [50, 51, 52, 53, 54, 55, 56, 57]]
etcShineConvTable = [[], [107], [100, 8, 9], [101, 18, 19], [102, 28, 29], [103, 38, 39], [104, 48, 49], [106, 68, 69], [105, 58, 59], []]
scenarioNameTable = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 33, 32, 35, 34, 31, 36, 37, 38, 39]

stageArc = readsection(open("stageArc.bin", 'rb'))
stageNames = [line.rstrip() for line in open("common/2d/stagename.txt")]
scenarioNames = [line.rstrip() for line in open("common/2d/scenarioname.txt")]
namesInStage = stageArc.objects[0]
for stageNumber, nameTable in enumerate(namesInStage.objects):
    shineStage = shineStageTable[stageNumber]
    stageName = stageNames[shineStage]
    print('    "%s",'%stageName.title())
    for scenarioNumber, archiveName in enumerate(nameTable.objects):
        archiveShort = archiveName.name1[:archiveName.name1.rfind('.')]
        if not os.path.exists("scene/"+archiveShort):
            continue
        scenarioName = archiveShort
        if shineStage < len(shineConvTable):
            if stageNumber < 20 or stageNumber > 52:
                shineTable = shineConvTable[shineStage]
            else:
                shineTable = etcShineConvTable[shineStage]
            if scenarioNumber < len(shineTable):
                shineId = shineTable[scenarioNumber]
                print(shineId)
                if shineId < len(scenarioNameTable):
                    scenarioNameIndex = scenarioNameTable[shineId]
                    print(scenarioNameIndex)
                    scenarioName = scenarioNames[scenarioNameIndex]
        print('    new SunshineSceneDesc("%s", "%s"),'%(archiveShort, scenarioName))

